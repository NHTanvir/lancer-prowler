//! XML output format — parity contract line 13.
//!
//! Minimal, dependency-free XML emitter. Schema: `<findings>` root with one
//! `<finding>` per CheckReport, each field as a child element. Resource and
//! compliance refs are nested.

use crate::models::CheckReport;
use anyhow::Context;
use std::fmt::Write;

pub fn render(findings: &[CheckReport]) -> String {
    let mut s = String::new();
    s.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    s.push('\n');
    s.push_str(&format!(
        r#"<findings tool="lancer-prowler" version="{}" generated_at="{}">"#,
        env!("CARGO_PKG_VERSION"),
        chrono::Utc::now().to_rfc3339(),
    ));
    s.push('\n');
    for f in findings {
        let _ = writeln!(s, "  <finding>");
        let _ = writeln!(s, "    <check_id>{}</check_id>", esc(&f.check_id));
        let _ = writeln!(s, "    <check_name>{}</check_name>", esc(&f.check_name));
        let _ = writeln!(s, "    <status>{}</status>", esc(&f.status.to_string()));
        let _ = writeln!(s, "    <severity>{}</severity>", esc(&f.severity.to_string()));
        let _ = writeln!(s, "    <provider>{}</provider>", esc(&f.provider));
        let _ = writeln!(s, "    <service>{}</service>", esc(&f.service));
        let _ = writeln!(s, "    <account_id>{}</account_id>", esc(&f.account_id));
        let _ = writeln!(s, "    <region>{}</region>", esc(&f.region));
        let _ = writeln!(s, "    <resource_id>{}</resource_id>", esc(&f.resource_id));
        let _ = writeln!(s, "    <resource_arn>{}</resource_arn>", esc(&f.resource_arn));
        let _ = writeln!(s, "    <status_extended>{}</status_extended>", esc(&f.status_extended));
        let _ = writeln!(s, "    <timestamp>{}</timestamp>", esc(&f.timestamp));
        if !f.compliance.is_empty() {
            let _ = writeln!(s, "    <compliance>");
            for c in &f.compliance {
                let _ = writeln!(
                    s,
                    "      <ref framework=\"{}\" control_id=\"{}\"/>",
                    esc(&c.framework),
                    esc(&c.control_id),
                );
            }
            let _ = writeln!(s, "    </compliance>");
        }
        let _ = writeln!(s, "  </finding>");
    }
    s.push_str("</findings>\n");
    s
}

pub fn write_xml(findings: &[CheckReport], path: &str) -> anyhow::Result<()> {
    let body = render(findings);
    std::fs::write(path, body).with_context(|| format!("Failed to write XML to: {path}"))?;
    Ok(())
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\n' && c != '\r' && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}
