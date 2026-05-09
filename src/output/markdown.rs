//! Markdown summary output — handy for pasting into Slack/Notion or pull-request
//! comments. Groups findings by status, by severity, and by service.

use crate::models::{CheckReport, Severity, Status};
use anyhow::Context;
use std::collections::BTreeMap;
use std::fmt::Write;

pub fn render(findings: &[CheckReport]) -> String {
    let mut buf = String::new();

    let total = findings.len();
    let pass = findings.iter().filter(|f| f.status == Status::Pass).count();
    let fail = findings.iter().filter(|f| f.status == Status::Fail).count();
    let muted = findings.iter().filter(|f| f.status == Status::Muted).count();

    let _ = writeln!(buf, "# lancer-prowler scan summary\n");
    let _ = writeln!(
        buf,
        "**Generated:** {}  \n**Total findings:** {}  \n**Pass / Fail / Muted:** {} / {} / {}\n",
        chrono::Utc::now().to_rfc3339(),
        total,
        pass,
        fail,
        muted,
    );

    let by_severity: BTreeMap<String, Vec<&CheckReport>> =
        findings.iter().fold(BTreeMap::new(), |mut acc, f| {
            acc.entry(severity_key(&f.severity)).or_default().push(f);
            acc
        });
    let _ = writeln!(buf, "## Findings by severity\n");
    let _ = writeln!(buf, "| Severity | Count |");
    let _ = writeln!(buf, "|----------|------:|");
    for (sev, items) in &by_severity {
        let _ = writeln!(buf, "| {} | {} |", sev, items.len());
    }

    let _ = writeln!(buf, "\n## Failing findings\n");
    let _ = writeln!(buf, "| Severity | Check | Service | Account | Region | Resource |");
    let _ = writeln!(buf, "|----------|-------|---------|---------|--------|----------|");
    for f in findings.iter().filter(|f| f.status == Status::Fail) {
        let _ = writeln!(
            buf,
            "| {} | `{}` | {} | {} | {} | `{}` |",
            f.severity, f.check_id, f.service, f.account_id, f.region, f.resource_id,
        );
    }

    buf
}

fn severity_key(s: &Severity) -> String {
    match s {
        Severity::Critical => "1. CRITICAL".to_string(),
        Severity::High => "2. HIGH".to_string(),
        Severity::Medium => "3. MEDIUM".to_string(),
        Severity::Low => "4. LOW".to_string(),
        Severity::Informational => "5. INFORMATIONAL".to_string(),
    }
}

pub fn write_markdown(findings: &[CheckReport], path: &str) -> anyhow::Result<()> {
    let content = render(findings);
    std::fs::write(path, content)
        .with_context(|| format!("Failed to write markdown to: {path}"))?;
    Ok(())
}
