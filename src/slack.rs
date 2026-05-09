//! Slack webhook notification — parity with upstream `--slack`.
//!
//! Posts a markdown summary of the scan to an incoming-webhook URL. The webhook
//! URL comes from (in order of preference):
//! 1. `--slack-webhook <URL>` command-line arg
//! 2. `SLACK_WEBHOOK_URL` environment variable
//! 3. otherwise no-op with a warning.

use crate::models::{CheckReport, Severity, Status};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct SlackPayload<'a> {
    text: &'a str,
    blocks: Vec<SlackBlock<'a>>,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum SlackBlock<'a> {
    #[serde(rename = "header")]
    Header { text: SlackText<'a> },
    #[serde(rename = "section")]
    Section { text: SlackText<'a> },
    #[serde(rename = "divider")]
    Divider,
}

#[derive(Serialize)]
struct SlackText<'a> {
    #[serde(rename = "type")]
    text_type: &'a str,
    text: String,
}

pub fn resolve_webhook(arg_override: &Option<String>) -> Option<String> {
    if let Some(u) = arg_override.as_ref() {
        if !u.is_empty() {
            return Some(u.clone());
        }
    }
    std::env::var("SLACK_WEBHOOK_URL").ok().filter(|s| !s.is_empty())
}

pub fn build_summary_text(findings: &[CheckReport]) -> String {
    let total = findings.len();
    let pass = findings.iter().filter(|f| f.status == Status::Pass).count();
    let fail = findings.iter().filter(|f| f.status == Status::Fail).count();
    let muted = findings.iter().filter(|f| f.status == Status::Muted).count();
    let crit = sev_count(findings, &Severity::Critical);
    let high = sev_count(findings, &Severity::High);
    let med = sev_count(findings, &Severity::Medium);
    let low = sev_count(findings, &Severity::Low);

    let mut top_services: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.status == Status::Fail) {
        *top_services.entry(f.service.clone()).or_default() += 1;
    }
    let mut top: Vec<_> = top_services.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    top.truncate(5);

    let mut s = String::new();
    s.push_str(&format!(
        "*lancer-prowler scan*\nTotal: *{total}*  •  PASS: {pass}  •  *FAIL: {fail}*  •  MUTED: {muted}\n"
    ));
    s.push_str(&format!(
        "Severity → CRITICAL: *{crit}* | HIGH: *{high}* | MEDIUM: {med} | LOW: {low}\n"
    ));
    if !top.is_empty() {
        s.push_str("\nTop failing services:\n");
        for (svc, c) in &top {
            s.push_str(&format!("• `{svc}` — {c}\n"));
        }
    }
    s
}

fn sev_count(findings: &[CheckReport], sev: &Severity) -> usize {
    findings
        .iter()
        .filter(|f| f.status == Status::Fail && std::mem::discriminant(&f.severity) == std::mem::discriminant(sev))
        .count()
}

pub fn post_summary(webhook_url: &str, findings: &[CheckReport]) -> anyhow::Result<()> {
    let summary = build_summary_text(findings);
    let payload = SlackPayload {
        text: "lancer-prowler scan finished",
        blocks: vec![
            SlackBlock::Header {
                text: SlackText {
                    text_type: "plain_text",
                    text: "lancer-prowler scan finished".to_string(),
                },
            },
            SlackBlock::Section {
                text: SlackText {
                    text_type: "mrkdwn",
                    text: summary,
                },
            },
            SlackBlock::Divider,
        ],
    };
    let body = serde_json::to_string(&payload)?;

    // No HTTP client crate available, but we can use the URL + curl as a
    // fallback. For now, write to a local fallback file and emit a tracing log.
    // Real implementations should use ureq/reqwest. The fallback prevents the
    // CLI from crashing in offline tests and still surfaces what would be sent.
    if let Some(path) = std::env::var("LANCER_SLACK_DRYRUN").ok() {
        std::fs::write(&path, &body).ok();
        tracing::info!("Slack webhook (dry run): wrote payload to {path}");
        return Ok(());
    }

    tracing::info!("Posting Slack summary to {}", webhook_url);
    match post_blocking(webhook_url, &body) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!("Slack webhook POST failed: {e}");
            // Don't fail the scan because of a notification problem.
            Ok(())
        }
    }
}

/// Minimal blocking HTTPS POST using the system `curl` binary so we don't pull
/// in a heavy HTTP client. If `curl` is unavailable, the function returns Err.
fn post_blocking(url: &str, body: &str) -> anyhow::Result<()> {
    use std::process::{Command, Stdio};
    let status = Command::new("curl")
        .arg("-sS")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("--data")
        .arg(body)
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn curl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("curl exit: {status}"))
    }
}
