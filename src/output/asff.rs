//! AWS Security Finding Format (ASFF) JSON output.
//!
//! This is the file-emitted form of ASFF (the same schema Security Hub accepts
//! via `batch_import_findings`). Splitting it from `security_hub.rs` lets users
//! produce ASFF JSON without uploading.

use crate::models::{CheckReport, Severity, Status};
use anyhow::Context;
use serde::Serialize;

#[derive(Serialize)]
pub struct AsffDocument {
    #[serde(rename = "Findings")]
    pub findings: Vec<AsffFinding>,
}

#[derive(Serialize)]
pub struct AsffFinding {
    #[serde(rename = "SchemaVersion")]
    pub schema_version: &'static str,
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "ProductArn")]
    pub product_arn: String,
    #[serde(rename = "GeneratorId")]
    pub generator_id: String,
    #[serde(rename = "AwsAccountId")]
    pub aws_account_id: String,
    #[serde(rename = "Types")]
    pub types: Vec<&'static str>,
    #[serde(rename = "FirstObservedAt")]
    pub first_observed_at: String,
    #[serde(rename = "LastObservedAt")]
    pub last_observed_at: String,
    #[serde(rename = "CreatedAt")]
    pub created_at: String,
    #[serde(rename = "UpdatedAt")]
    pub updated_at: String,
    #[serde(rename = "Severity")]
    pub severity: AsffSeverity,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Resources")]
    pub resources: Vec<AsffResource>,
    #[serde(rename = "Compliance")]
    pub compliance: AsffCompliance,
    #[serde(rename = "Workflow")]
    pub workflow: AsffWorkflow,
    #[serde(rename = "RecordState")]
    pub record_state: &'static str,
}

#[derive(Serialize)]
pub struct AsffSeverity {
    #[serde(rename = "Label")]
    pub label: String,
}

#[derive(Serialize)]
pub struct AsffResource {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Type")]
    pub resource_type: String,
    #[serde(rename = "Region")]
    pub region: String,
}

#[derive(Serialize)]
pub struct AsffCompliance {
    #[serde(rename = "Status")]
    pub status: &'static str,
    #[serde(rename = "RelatedRequirements")]
    pub related_requirements: Vec<String>,
}

#[derive(Serialize)]
pub struct AsffWorkflow {
    #[serde(rename = "Status")]
    pub status: &'static str,
}

fn sev_label(s: &Severity) -> String {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Informational => "INFORMATIONAL",
    }
    .to_string()
}

pub fn build_document(findings: &[CheckReport]) -> AsffDocument {
    let now = chrono::Utc::now().to_rfc3339();
    let mut out = Vec::with_capacity(findings.len());
    for f in findings {
        let region = if f.region.is_empty() {
            "us-east-1".to_string()
        } else {
            f.region.clone()
        };
        let account = if f.account_id.is_empty() {
            "000000000000".to_string()
        } else {
            f.account_id.clone()
        };
        let related_requirements: Vec<String> = f
            .compliance
            .iter()
            .map(|c| format!("{} {}", c.framework, c.control_id))
            .collect();
        let compliance_status = if matches!(f.status, Status::Pass) {
            "PASSED"
        } else if matches!(f.status, Status::Fail) {
            "FAILED"
        } else {
            "NOT_AVAILABLE"
        };
        let workflow_status = if matches!(f.status, Status::Pass) {
            "RESOLVED"
        } else {
            "NEW"
        };
        out.push(AsffFinding {
            schema_version: "2018-10-08",
            id: format!(
                "arn:aws:securityhub:{}:{}:product/{}/default/{}:{}",
                region, account, account, &f.check_id, &f.resource_id
            ),
            product_arn: format!(
                "arn:aws:securityhub:{}:{}:product/{}/default",
                region, account, account
            ),
            generator_id: format!("lancer-prowler/{}", &f.check_id),
            aws_account_id: account.clone(),
            types: vec![
                "Software and Configuration Checks/Industry and Regulatory Standards",
            ],
            first_observed_at: now.clone(),
            last_observed_at: now.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
            severity: AsffSeverity {
                label: sev_label(&f.severity),
            },
            title: f.check_name.clone(),
            description: f.status_extended.clone(),
            resources: vec![AsffResource {
                id: if f.resource_arn.is_empty() {
                    f.resource_id.clone()
                } else {
                    f.resource_arn.clone()
                },
                resource_type: f.service.clone(),
                region: region.clone(),
            }],
            compliance: AsffCompliance {
                status: compliance_status,
                related_requirements,
            },
            workflow: AsffWorkflow {
                status: workflow_status,
            },
            record_state: "ACTIVE",
        });
    }
    AsffDocument { findings: out }
}

pub fn write_asff(findings: &[CheckReport], path: &str) -> anyhow::Result<()> {
    let doc = build_document(findings);
    let json =
        serde_json::to_string_pretty(&doc).context("Failed to serialize ASFF document")?;
    std::fs::write(path, json).with_context(|| format!("Failed to write ASFF JSON to: {path}"))?;
    Ok(())
}
