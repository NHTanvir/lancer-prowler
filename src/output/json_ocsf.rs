use crate::models::{CheckReport, Status};
use anyhow::Context;
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
struct OcsfFinding {
    class_uid: u32,
    class_name: &'static str,
    category_uid: u32,
    category_name: &'static str,
    activity_id: u32,
    time: i64,
    severity_id: u8,
    severity: String,
    status_id: u8,
    status: String,
    finding: OcsfFindingDetail,
    cloud: OcsfCloud,
    resources: Vec<OcsfResource>,
    compliance: OcsfCompliance,
}

#[derive(Serialize)]
struct OcsfFindingDetail {
    uid: String,
    title: String,
    desc: String,
}

#[derive(Serialize)]
struct OcsfCloud {
    provider: String,
    account_uid: String,
    region: String,
}

#[derive(Serialize)]
struct OcsfResource {
    uid: String,
    name: String,
    #[serde(rename = "type")]
    resource_type: String,
}

#[derive(Serialize)]
struct OcsfCompliance {
    control: String,
    frameworks: Vec<String>,
}

fn to_ocsf(report: &CheckReport) -> OcsfFinding {
    let time_ms = chrono::DateTime::parse_from_rfc3339(&report.timestamp)
        .map(|dt| dt.timestamp_millis())
        .unwrap_or_else(|_| chrono::Utc::now().timestamp_millis());

    let control_refs: Vec<String> = report
        .compliance
        .iter()
        .map(|c| format!("{} {}", c.framework, c.control_id))
        .collect();

    let frameworks: Vec<String> = report
        .compliance
        .iter()
        .map(|c| c.framework.clone())
        .collect();

    let status_label = match report.status {
        Status::Pass => "Pass",
        Status::Fail => "Fail",
        Status::Muted => "Muted",
        Status::Unknown => "Unknown",
    }
    .to_string();

    OcsfFinding {
        class_uid: 2003,
        class_name: "Compliance Finding",
        category_uid: 2,
        category_name: "Findings",
        activity_id: 1,
        time: time_ms,
        severity_id: report.severity.ocsf_id(),
        severity: report.severity.to_string(),
        status_id: report.status.ocsf_id(),
        status: status_label,
        finding: OcsfFindingDetail {
            uid: report.check_id.clone(),
            title: report.check_name.clone(),
            desc: report.status_extended.clone(),
        },
        cloud: OcsfCloud {
            provider: report.provider.clone(),
            account_uid: report.account_id.clone(),
            region: report.region.clone(),
        },
        resources: vec![OcsfResource {
            uid: report.resource_arn.clone(),
            name: report.resource_id.clone(),
            resource_type: report.service.clone(),
        }],
        compliance: OcsfCompliance {
            control: control_refs.join(", "),
            frameworks,
        },
    }
}

pub fn write_json_ocsf(findings: &[CheckReport], path: &str) -> anyhow::Result<()> {
    let ocsf_findings: Vec<Value> = findings
        .iter()
        .map(|f| serde_json::to_value(to_ocsf(f)))
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to serialize findings to OCSF")?;

    let output = serde_json::to_string_pretty(&ocsf_findings)
        .context("Failed to serialize OCSF JSON")?;

    std::fs::write(path, output)
        .with_context(|| format!("Failed to write OCSF JSON to: {path}"))?;

    Ok(())
}
