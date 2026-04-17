use crate::models::CheckReport;
use anyhow::Context;

pub fn write_csv(findings: &[CheckReport], path: &str) -> anyhow::Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("Failed to open CSV output path: {path}"))?;

    writer.write_record([
        "check_id",
        "check_name",
        "status",
        "status_extended",
        "severity",
        "resource_id",
        "resource_arn",
        "region",
        "provider",
        "service",
        "account_id",
        "timestamp",
    ])?;

    for f in findings {
        writer.write_record([
            &f.check_id,
            &f.check_name,
            &f.status.to_string(),
            &f.status_extended,
            &f.severity.to_string(),
            &f.resource_id,
            &f.resource_arn,
            &f.region,
            &f.provider,
            &f.service,
            &f.account_id,
            &f.timestamp,
        ])?;
    }

    writer.flush().context("Failed to flush CSV writer")?;
    Ok(())
}
