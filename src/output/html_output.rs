//! HTML output — renders security findings as a styled HTML report.

use crate::models::CheckReport;

/// Write HTML findings report to the given file path.
pub fn write_html(findings: &[CheckReport], path: &str) -> anyhow::Result<()> {
    let html = render_html(findings)?;
    std::fs::write(path, html)?;
    Ok(())
}

/// Render findings as an HTML string.
pub fn render_html(findings: &[CheckReport]) -> anyhow::Result<String> {
    let total = findings.len();
    let failed = findings
        .iter()
        .filter(|f| matches!(f.status, crate::models::Status::Fail))
        .count();
    let passed = findings
        .iter()
        .filter(|f| matches!(f.status, crate::models::Status::Pass))
        .count();

    let rows = findings
        .iter()
        .map(|f| {
            let status_class = match f.status {
                crate::models::Status::Fail => "fail",
                crate::models::Status::Pass => "pass",
                _ => "unknown",
            };
            format!(
                "<tr class=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                status_class,
                html_escape(&f.check_id),
                html_escape(&f.check_name),
                html_escape(&format!("{:?}", f.status)),
                html_escape(&format!("{:?}", f.severity)),
                html_escape(&f.resource_id),
                html_escape(&f.region),
                html_escape(&f.status_extended),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Lancer-Prowler Security Report</title>
<style>
body {{ font-family: sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
h1 {{ color: #e94560; }}
.summary {{ display: flex; gap: 20px; margin: 20px 0; }}
.card {{ background: #16213e; padding: 15px 25px; border-radius: 8px; }}
.card.fail {{ border-left: 4px solid #e94560; }}
.card.pass {{ border-left: 4px solid #0f3460; }}
table {{ width: 100%; border-collapse: collapse; background: #16213e; }}
th {{ background: #0f3460; padding: 10px; text-align: left; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #0f3460; font-size: 13px; }}
tr.fail td {{ color: #ff6b6b; }}
tr.pass td {{ color: #69ff69; }}
tr.unknown td {{ color: #ffff69; }}
</style>
</head>
<body>
<h1>Lancer-Prowler Security Report</h1>
<div class="summary">
  <div class="card fail"><strong>{failed}</strong><br>Findings</div>
  <div class="card pass"><strong>{passed}</strong><br>Passed</div>
  <div class="card"><strong>{total}</strong><br>Total</div>
</div>
<table>
<thead><tr><th>Check ID</th><th>Check Name</th><th>Status</th><th>Severity</th><th>Resource</th><th>Region</th><th>Details</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"#,
        failed = failed,
        passed = passed,
        total = total,
        rows = rows
    ))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
