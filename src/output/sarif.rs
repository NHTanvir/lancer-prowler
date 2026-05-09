//! SARIF v2.1.0 output — for GitHub Code Scanning integration.
//!
//! Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
//! Each `CheckReport` produces one SARIF `Result`. The set of unique check IDs
//! becomes the SARIF `rules` array.

use crate::models::{CheckReport, Severity, Status};
use anyhow::Context;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct SarifDocument {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    #[serde(rename = "automationDetails")]
    automation_details: SarifAutomationDetails,
}

#[derive(Serialize)]
struct SarifAutomationDetails {
    id: String,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    version: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifText,
    #[serde(rename = "fullDescription")]
    full_description: SarifText,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifConfig,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
struct SarifRuleProperties {
    tags: Vec<String>,
    #[serde(rename = "security-severity", skip_serializing_if = "Option::is_none")]
    security_severity: Option<String>,
}

#[derive(Serialize)]
struct SarifConfig {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifText {
    text: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifText,
    locations: Vec<SarifLocation>,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: BTreeMap<String, String>,
    properties: SarifResultProperties,
}

#[derive(Serialize)]
struct SarifResultProperties {
    provider: String,
    service: String,
    region: String,
    #[serde(rename = "accountId")]
    account_id: String,
    status: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

fn severity_to_level(s: &Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Informational => "none",
    }
}

fn severity_to_security_score(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "2.5",
        Severity::Informational => "0.0",
    }
}

pub fn build_document(findings: &[CheckReport]) -> SarifDocument {
    // Build dedup'd rules
    let mut rules_map: BTreeMap<String, SarifRule> = BTreeMap::new();
    for f in findings {
        rules_map.entry(f.check_id.clone()).or_insert_with(|| {
            let tags: Vec<String> = std::iter::once("security".to_string())
                .chain(std::iter::once(f.provider.clone()))
                .chain(std::iter::once(f.service.clone()))
                .chain(f.compliance.iter().map(|c| c.framework.clone()))
                .collect();
            SarifRule {
                id: f.check_id.clone(),
                name: f.check_name.clone(),
                short_description: SarifText { text: f.check_name.clone() },
                full_description: SarifText {
                    text: format!("{} ({}, {})", f.check_name, f.provider, f.service),
                },
                help_uri: Some(format!(
                    "https://hub.prowler.com/check/{}",
                    f.check_id
                )),
                default_configuration: SarifConfig {
                    level: severity_to_level(&f.severity),
                },
                properties: SarifRuleProperties {
                    tags,
                    security_severity: Some(
                        severity_to_security_score(&f.severity).to_string(),
                    ),
                },
            }
        });
    }
    let rules: Vec<SarifRule> = rules_map.into_values().collect();

    let results: Vec<SarifResult> = findings
        .iter()
        .filter(|f| !matches!(f.status, Status::Pass)) // SARIF carries failures
        .map(|f| {
            let mut fingerprints = BTreeMap::new();
            fingerprints.insert(
                "primaryLocationLineHash".to_string(),
                format!("{}:{}:{}", f.check_id, f.account_id, f.resource_arn),
            );
            SarifResult {
                rule_id: f.check_id.clone(),
                level: severity_to_level(&f.severity),
                message: SarifText {
                    text: f.status_extended.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: if f.resource_arn.is_empty() {
                                format!("cloud://{}/{}", f.provider, f.resource_id)
                            } else {
                                f.resource_arn.clone()
                            },
                        },
                    },
                }],
                partial_fingerprints: fingerprints,
                properties: SarifResultProperties {
                    provider: f.provider.clone(),
                    service: f.service.clone(),
                    region: f.region.clone(),
                    account_id: f.account_id.clone(),
                    status: f.status.to_string(),
                },
            }
        })
        .collect();

    SarifDocument {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "lancer-prowler",
                    information_uri: "https://github.com/NHTanvir/lancer-prowler",
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results,
            automation_details: SarifAutomationDetails {
                id: format!("lancer-prowler-scan/{}", chrono::Utc::now().to_rfc3339()),
            },
        }],
    }
}

pub fn write_sarif(findings: &[CheckReport], path: &str) -> anyhow::Result<()> {
    let doc = build_document(findings);
    let json =
        serde_json::to_string_pretty(&doc).context("Failed to serialize SARIF document")?;
    std::fs::write(path, json).with_context(|| format!("Failed to write SARIF to: {path}"))?;
    Ok(())
}
