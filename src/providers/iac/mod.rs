//! Infrastructure-as-code provider (stub).
//!
//! Scans Terraform / CloudFormation / Dockerfile / Kubernetes-manifest files
//! for security misconfigurations *before* they reach the cloud.
//!
//! Real implementation would walk a target directory, parse files with HCL /
//! YAML / Dockerfile lexers, and run pattern-matchers against AST nodes.

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;
use std::path::Path;

pub struct IacProvider {
    pub root: String,
}

impl IacProvider {
    pub fn new_stub(root: String) -> Self {
        Self { root }
    }
}

impl Provider for IacProvider {
    fn name(&self) -> &str { "Infrastructure as Code" }
    fn provider_id(&self) -> &str { "iac" }
    fn account_id(&self) -> &str { "local" }
    fn regions(&self) -> Vec<String> { vec!["local".to_string()] }
}

pub const FILE_TYPES: &[&str] = &[
    "terraform",
    "cloudformation",
    "dockerfile",
    "kubernetes",
    "helm",
    "kustomize",
];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("terraform_s3_no_public_acl", "terraform", Severity::Critical),
        meta("terraform_provider_pinned", "terraform", Severity::Medium),
        meta("cloudformation_no_hardcoded_credentials", "cloudformation", Severity::Critical),
        meta("dockerfile_no_root_user", "dockerfile", Severity::High),
        meta("dockerfile_pin_base_image", "dockerfile", Severity::Medium),
        meta("kubernetes_no_privileged_containers", "kubernetes", Severity::High),
        meta("kubernetes_namespace_resource_quota", "kubernetes", Severity::Low),
        meta("helm_chart_no_root", "helm", Severity::Medium),
    ]
}

pub fn scan_directory(root: &str) -> Vec<CheckReport> {
    let root_path = Path::new(root);
    let mut files = Vec::new();
    if root_path.exists() {
        walk(root_path, &mut files);
    }

    let mut out = vec![];
    for meta in sample_checks() {
        let status = if files.is_empty() {
            Status::Unknown
        } else {
            // Synthetic: alternate pass/fail based on file count parity.
            if (files.len() + meta.id.len()) % 2 == 0 {
                Status::Pass
            } else {
                Status::Fail
            }
        };
        out.push(CheckReport {
            check_id: meta.id.clone(),
            check_name: meta.name.clone(),
            status,
            status_extended: format!("Stub: scanned {} candidate file(s)", files.len()),
            severity: meta.severity.clone(),
            resource_id: root.to_string(),
            resource_arn: format!("iac://{}", root),
            region: "local".to_string(),
            provider: "iac".to_string(),
            service: meta.service.clone(),
            account_id: "local".to_string(),
            compliance: vec![ComplianceRef {
                framework: "cis_terraform_benchmark_v1.0.0".to_string(),
                control_id: "tbd".to_string(),
            }],
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    if !dir.is_dir() {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            walk(&path, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "tf" | "yaml" | "yml" | "json")
                || path.file_name().and_then(|n| n.to_str()) == Some("Dockerfile")
            {
                out.push(path);
            }
        } else if path.file_name().and_then(|n| n.to_str()) == Some("Dockerfile") {
            out.push(path);
        }
    }
}

fn meta(id: &str, service: &str, sev: Severity) -> CheckMetadata {
    CheckMetadata {
        id: id.to_string(),
        name: id.replace('_', " "),
        description: id.replace('_', " "),
        severity: sev,
        service: service.to_string(),
        provider: "iac".to_string(),
        compliance: vec![ComplianceRef {
            framework: "cis_terraform_benchmark_v1.0.0".to_string(),
            control_id: "tbd".to_string(),
        }],
    }
}
