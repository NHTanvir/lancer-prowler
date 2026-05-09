//! JSON-OCSF v1.1+ output — canonical for Prowler Cloud / SaaS ingestion.
//!
//! In addition to the core Compliance Finding shape, we emit the optional
//! fields plan.md called out (lines 276-280):
//!
//! - `relationships[]` — backing graph data for attack-path visualization.
//! - `console_url` — per-finding deep-link into the cloud provider's console.
//! - `remediation.code.aws_cli` / `remediation.code.terraform` — populate so
//!   downstream tools (Prowler Cloud, Claude Code remediation plugin) can act
//!   on findings.
//! - `threat_score` — when --threatscore is set, attach the scored value.

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
    metadata: OcsfMetadata,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    relationships: Vec<OcsfRelationship>,
    #[serde(skip_serializing_if = "Option::is_none")]
    console_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<OcsfRemediation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threat_score: Option<f32>,
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

#[derive(Serialize)]
struct OcsfMetadata {
    version: &'static str,
    product: OcsfProduct,
}

#[derive(Serialize)]
struct OcsfProduct {
    name: &'static str,
    vendor_name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct OcsfRelationship {
    #[serde(rename = "type")]
    rel_type: String,
    target_uid: String,
}

#[derive(Serialize)]
struct OcsfRemediation {
    desc: String,
    code: OcsfRemediationCode,
}

#[derive(Serialize)]
struct OcsfRemediationCode {
    #[serde(skip_serializing_if = "Option::is_none")]
    aws_cli: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terraform: Option<String>,
}

pub fn build_console_url(report: &CheckReport) -> Option<String> {
    match report.provider.as_str() {
        "aws" => Some(build_aws_console_url(report)),
        "azure" => Some(format!(
            "https://portal.azure.com/#@/resource/{}",
            report.resource_arn.trim_start_matches('/')
        )),
        "gcp" => Some(format!(
            "https://console.cloud.google.com/?project={}",
            report.account_id
        )),
        "kubernetes" => None,
        _ => None,
    }
}

fn build_aws_console_url(report: &CheckReport) -> String {
    let region = if report.region.is_empty() || report.region == "global" {
        "us-east-1".to_string()
    } else {
        report.region.clone()
    };
    match report.service.as_str() {
        "iam" => format!(
            "https://us-east-1.console.aws.amazon.com/iamv2/home#/users"
        ),
        "s3" => format!(
            "https://s3.console.aws.amazon.com/s3/buckets/{}",
            report.resource_id
        ),
        "ec2" => format!(
            "https://{}.console.aws.amazon.com/ec2/home?region={}",
            region, region
        ),
        "cloudtrail" => format!(
            "https://{}.console.aws.amazon.com/cloudtrail/home?region={}",
            region, region
        ),
        "kms" => format!(
            "https://{}.console.aws.amazon.com/kms/home?region={}",
            region, region
        ),
        "rds" => format!(
            "https://{}.console.aws.amazon.com/rds/home?region={}",
            region, region
        ),
        "lambda" => format!(
            "https://{}.console.aws.amazon.com/lambda/home?region={}",
            region, region
        ),
        _ => format!(
            "https://{}.console.aws.amazon.com/?region={}",
            region, region
        ),
    }
}

fn build_remediation(report: &CheckReport) -> Option<OcsfRemediation> {
    // Best-effort hand-coded remediation snippets for the most common check IDs.
    let (aws_cli, terraform, desc) = match report.check_id.as_str() {
        "iam_no_root_access_key" => (
            Some("aws iam delete-access-key --user-name <root> --access-key-id <id>".to_string()),
            None,
            "Delete the root user's access key in the IAM console or via the CLI command.",
        ),
        "s3_bucket_default_encryption" => (
            Some(format!(
                "aws s3api put-bucket-encryption --bucket {} --server-side-encryption-configuration '{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'",
                report.resource_id
            )),
            Some(format!(
                "resource \"aws_s3_bucket_server_side_encryption_configuration\" \"this\" {{\n  bucket = \"{}\"\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = \"AES256\"\n    }}\n  }}\n}}\n",
                report.resource_id
            )),
            "Enable server-side encryption on the bucket.",
        ),
        "ec2_ebs_default_encryption" => (
            Some("aws ec2 enable-ebs-encryption-by-default".to_string()),
            None,
            "Enable EBS encryption by default at the account level.",
        ),
        "kms_cmk_rotation_enabled" => (
            Some(format!(
                "aws kms enable-key-rotation --key-id {}",
                report.resource_id
            )),
            None,
            "Enable annual rotation on the KMS CMK.",
        ),
        "cloudtrail_multi_region_enabled" => (
            Some("aws cloudtrail create-trail --name lancer-multiregion --s3-bucket-name <bucket> --is-multi-region-trail".to_string()),
            None,
            "Create or update CloudTrail to be multi-region.",
        ),
        "guardduty_is_enabled" => (
            Some("aws guardduty create-detector --enable".to_string()),
            None,
            "Enable GuardDuty in the account.",
        ),
        _ => (None, None, ""),
    };
    if aws_cli.is_none() && terraform.is_none() {
        return None;
    }
    Some(OcsfRemediation {
        desc: desc.to_string(),
        code: OcsfRemediationCode { aws_cli, terraform },
    })
}

fn build_relationships(report: &CheckReport) -> Vec<OcsfRelationship> {
    let mut out = Vec::new();
    if !report.account_id.is_empty() {
        out.push(OcsfRelationship {
            rel_type: "located_in_account".into(),
            target_uid: report.account_id.clone(),
        });
    }
    if !report.region.is_empty() {
        out.push(OcsfRelationship {
            rel_type: "located_in_region".into(),
            target_uid: report.region.clone(),
        });
    }
    if !report.service.is_empty() {
        out.push(OcsfRelationship {
            rel_type: "service".into(),
            target_uid: report.service.clone(),
        });
    }
    out
}

fn compute_threat_score(report: &CheckReport) -> f32 {
    let base: f32 = match report.severity {
        crate::models::Severity::Critical => 9.5,
        crate::models::Severity::High => 7.5,
        crate::models::Severity::Medium => 5.0,
        crate::models::Severity::Low => 2.5,
        crate::models::Severity::Informational => 0.5,
    };
    if matches!(report.status, Status::Pass) {
        0.0
    } else if matches!(report.status, Status::Muted) {
        base * 0.25
    } else {
        base
    }
}

pub fn to_ocsf_value(report: &CheckReport, include_threatscore: bool) -> serde_json::Value {
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

    let finding = OcsfFinding {
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
        metadata: OcsfMetadata {
            version: "1.1.0",
            product: OcsfProduct {
                name: "lancer-prowler",
                vendor_name: "Lancer",
                version: env!("CARGO_PKG_VERSION"),
            },
        },
        relationships: build_relationships(report),
        console_url: build_console_url(report),
        remediation: build_remediation(report),
        threat_score: if include_threatscore {
            Some(compute_threat_score(report))
        } else {
            None
        },
    };

    serde_json::to_value(finding).unwrap_or(serde_json::Value::Null)
}

pub fn write_json_ocsf(findings: &[CheckReport], path: &str) -> anyhow::Result<()> {
    write_json_ocsf_with_options(findings, path, false)
}

pub fn write_json_ocsf_with_options(
    findings: &[CheckReport],
    path: &str,
    include_threatscore: bool,
) -> anyhow::Result<()> {
    let ocsf_findings: Vec<Value> = findings
        .iter()
        .map(|f| to_ocsf_value(f, include_threatscore))
        .collect();

    let output = serde_json::to_string_pretty(&ocsf_findings)
        .context("Failed to serialize OCSF JSON")?;

    std::fs::write(path, output)
        .with_context(|| format!("Failed to write OCSF JSON to: {path}"))?;

    Ok(())
}
