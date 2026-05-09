//! Imported-scan ingestion — parity with upstream `--ingest`.
//!
//! Reads a previous scan output (CSV / JSON-OCSF / SARIF) and reconstructs
//! a `Vec<CheckReport>` so it can be re-emitted in another format.

use crate::models::{CheckReport, ComplianceRef, Severity, Status};
use anyhow::{anyhow, Context};
use serde_json::Value;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestFormat {
    Csv,
    JsonOcsf,
    JsonAsff,
    Sarif,
}

impl IngestFormat {
    pub fn detect_from_path(path: &str) -> Option<Self> {
        let p = path.to_lowercase();
        if p.ends_with(".csv") {
            Some(Self::Csv)
        } else if p.ends_with(".sarif") || p.ends_with(".sarif.json") {
            Some(Self::Sarif)
        } else if p.ends_with(".asff.json") {
            Some(Self::JsonAsff)
        } else if p.ends_with(".ocsf.json") || p.ends_with(".json") {
            Some(Self::JsonOcsf)
        } else {
            None
        }
    }
}

pub fn ingest_file(path: &str, format: Option<IngestFormat>) -> anyhow::Result<Vec<CheckReport>> {
    let fmt = format
        .or_else(|| IngestFormat::detect_from_path(path))
        .ok_or_else(|| anyhow!("Cannot detect ingest format for path: {path}. Pass --format."))?;

    let bytes = std::fs::read(Path::new(path))
        .with_context(|| format!("Failed to read ingest file: {path}"))?;

    match fmt {
        IngestFormat::Csv => ingest_csv(&bytes),
        IngestFormat::JsonOcsf => ingest_ocsf(&bytes),
        IngestFormat::JsonAsff => ingest_asff(&bytes),
        IngestFormat::Sarif => ingest_sarif(&bytes),
    }
}

pub fn ingest_file_from_bytes(bytes: &[u8], format: &str) -> anyhow::Result<Vec<CheckReport>> {
    match format.to_ascii_lowercase().as_str() {
        "csv" => ingest_csv(bytes),
        "json-ocsf" | "ocsf" | "json" => ingest_ocsf(bytes),
        "json-asff" | "asff" => ingest_asff(bytes),
        "sarif" => ingest_sarif(bytes),
        other => Err(anyhow!("Unknown ingest format: {other}")),
    }
}

fn ingest_csv(bytes: &[u8]) -> anyhow::Result<Vec<CheckReport>> {
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).from_reader(bytes);
    let headers = rdr.headers().context("CSV has no headers")?.clone();
    let mut out = Vec::new();

    for result in rdr.records() {
        let rec = result.context("Failed to read CSV record")?;
        let get = |k: &str| -> String {
            headers
                .iter()
                .position(|h| h.eq_ignore_ascii_case(k))
                .and_then(|i| rec.get(i))
                .unwrap_or("")
                .to_string()
        };
        out.push(CheckReport {
            check_id: get("check_id"),
            check_name: get("check_name"),
            status: parse_status(&get("status")),
            status_extended: get("status_extended"),
            severity: parse_severity(&get("severity")),
            resource_id: get("resource_id"),
            resource_arn: get("resource_arn"),
            region: get("region"),
            provider: get("provider"),
            service: get("service"),
            account_id: get("account_id"),
            compliance: vec![],
            timestamp: if get("timestamp").is_empty() {
                chrono::Utc::now().to_rfc3339()
            } else {
                get("timestamp")
            },
        });
    }
    Ok(out)
}

fn ingest_ocsf(bytes: &[u8]) -> anyhow::Result<Vec<CheckReport>> {
    let v: Value = serde_json::from_slice(bytes).context("OCSF JSON parse failed")?;
    let arr = v.as_array().ok_or_else(|| anyhow!("OCSF JSON: expected top-level array"))?;
    let mut out = Vec::new();
    for item in arr {
        let finding = &item["finding"];
        let resources = item["resources"].as_array().cloned().unwrap_or_default();
        let cloud = &item["cloud"];

        out.push(CheckReport {
            check_id: finding["uid"].as_str().unwrap_or("").to_string(),
            check_name: finding["title"].as_str().unwrap_or("").to_string(),
            status: parse_status(item["status"].as_str().unwrap_or("Unknown")),
            status_extended: finding["desc"].as_str().unwrap_or("").to_string(),
            severity: parse_severity(item["severity"].as_str().unwrap_or("LOW")),
            resource_id: resources
                .first()
                .and_then(|r| r["name"].as_str())
                .unwrap_or("")
                .to_string(),
            resource_arn: resources
                .first()
                .and_then(|r| r["uid"].as_str())
                .unwrap_or("")
                .to_string(),
            region: cloud["region"].as_str().unwrap_or("").to_string(),
            provider: cloud["provider"].as_str().unwrap_or("").to_string(),
            service: resources
                .first()
                .and_then(|r| r["type"].as_str())
                .unwrap_or("")
                .to_string(),
            account_id: cloud["account_uid"].as_str().unwrap_or("").to_string(),
            compliance: parse_ocsf_compliance(&item["compliance"]),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }
    Ok(out)
}

fn parse_ocsf_compliance(v: &Value) -> Vec<ComplianceRef> {
    let frameworks = v["frameworks"].as_array().cloned().unwrap_or_default();
    let control = v["control"].as_str().unwrap_or("").to_string();
    frameworks
        .into_iter()
        .filter_map(|f| f.as_str().map(|s| s.to_string()))
        .map(|framework| ComplianceRef {
            framework,
            control_id: control.clone(),
        })
        .collect()
}

fn ingest_asff(bytes: &[u8]) -> anyhow::Result<Vec<CheckReport>> {
    let v: Value = serde_json::from_slice(bytes).context("ASFF JSON parse failed")?;
    let findings = v["Findings"]
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("ASFF JSON: expected `Findings` array"))?;
    let mut out = Vec::new();
    for item in findings {
        let resource = item["Resources"].as_array().and_then(|a| a.first()).cloned();
        let resource_id = resource
            .as_ref()
            .and_then(|r| r["Id"].as_str())
            .unwrap_or("")
            .to_string();
        let region = resource
            .as_ref()
            .and_then(|r| r["Region"].as_str())
            .unwrap_or("")
            .to_string();
        let service = resource
            .as_ref()
            .and_then(|r| r["Type"].as_str())
            .unwrap_or("")
            .to_string();
        let status_str = item["Compliance"]["Status"].as_str().unwrap_or("");
        let status = match status_str {
            "PASSED" => Status::Pass,
            "FAILED" => Status::Fail,
            _ => Status::Unknown,
        };
        let related: Vec<ComplianceRef> = item["Compliance"]["RelatedRequirements"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| r.as_str().map(parse_asff_requirement))
            .collect();
        out.push(CheckReport {
            check_id: item["GeneratorId"]
                .as_str()
                .unwrap_or("")
                .split('/')
                .last()
                .unwrap_or("")
                .to_string(),
            check_name: item["Title"].as_str().unwrap_or("").to_string(),
            status,
            status_extended: item["Description"].as_str().unwrap_or("").to_string(),
            severity: parse_severity(
                item["Severity"]["Label"].as_str().unwrap_or("LOW"),
            ),
            resource_id: resource_id.clone(),
            resource_arn: resource_id,
            region,
            provider: "aws".to_string(),
            service,
            account_id: item["AwsAccountId"].as_str().unwrap_or("").to_string(),
            compliance: related,
            timestamp: item["UpdatedAt"]
                .as_str()
                .unwrap_or(&chrono::Utc::now().to_rfc3339())
                .to_string(),
        });
    }
    Ok(out)
}

fn parse_asff_requirement(req: &str) -> ComplianceRef {
    match req.split_once(' ') {
        Some((fw, ctrl)) => ComplianceRef {
            framework: fw.to_string(),
            control_id: ctrl.to_string(),
        },
        None => ComplianceRef {
            framework: req.to_string(),
            control_id: String::new(),
        },
    }
}

fn ingest_sarif(bytes: &[u8]) -> anyhow::Result<Vec<CheckReport>> {
    let v: Value = serde_json::from_slice(bytes).context("SARIF JSON parse failed")?;
    let runs = v["runs"].as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for run in runs {
        let results = run["results"].as_array().cloned().unwrap_or_default();
        for r in results {
            let rule_id = r["ruleId"].as_str().unwrap_or("").to_string();
            let message = r["message"]["text"].as_str().unwrap_or("").to_string();
            let level = r["level"].as_str().unwrap_or("warning");
            let resource = r["locations"]
                .as_array()
                .and_then(|l| l.first())
                .and_then(|l| l["physicalLocation"]["artifactLocation"]["uri"].as_str())
                .unwrap_or("")
                .to_string();
            let props = &r["properties"];
            out.push(CheckReport {
                check_id: rule_id.clone(),
                check_name: rule_id,
                status: Status::Fail, // SARIF carries failures
                status_extended: message,
                severity: match level {
                    "error" => Severity::High,
                    "warning" => Severity::Medium,
                    "note" => Severity::Low,
                    _ => Severity::Informational,
                },
                resource_id: resource.clone(),
                resource_arn: resource,
                region: props["region"].as_str().unwrap_or("").to_string(),
                provider: props["provider"].as_str().unwrap_or("").to_string(),
                service: props["service"].as_str().unwrap_or("").to_string(),
                account_id: props["accountId"].as_str().unwrap_or("").to_string(),
                compliance: vec![],
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }
    }
    Ok(out)
}

fn parse_status(s: &str) -> Status {
    match s.to_ascii_uppercase().as_str() {
        "PASS" | "PASSED" => Status::Pass,
        "FAIL" | "FAILED" => Status::Fail,
        "MUTED" => Status::Muted,
        _ => Status::Unknown,
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        "INFORMATIONAL" | "INFO" => Severity::Informational,
        _ => Severity::Medium,
    }
}
