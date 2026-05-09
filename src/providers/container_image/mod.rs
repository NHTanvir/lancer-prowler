//! Container-image scanning (stub).
//!
//! Inspects a built container image for vulnerabilities, misconfiguration, and
//! secrets. Real implementation would shell out to `trivy` / `grype` or pull
//! the image and walk its layers locally.

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct ContainerImageProvider {
    pub image_ref: String,
}

impl ContainerImageProvider {
    pub fn new_stub(image_ref: String) -> Self {
        Self { image_ref }
    }
}

impl Provider for ContainerImageProvider {
    fn name(&self) -> &str { "Container Image" }
    fn provider_id(&self) -> &str { "container-image" }
    fn account_id(&self) -> &str { "local" }
    fn regions(&self) -> Vec<String> { vec!["local".to_string()] }
}

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("image_no_high_severity_cve", "vulnerability", Severity::High),
        meta("image_no_secret_in_layers", "secrets", Severity::Critical),
        meta("image_non_root_user", "config", Severity::High),
        meta("image_pinned_digest", "config", Severity::Medium),
        meta("image_no_known_malware", "malware", Severity::Critical),
        meta("image_distroless_preferred", "config", Severity::Low),
    ]
}

pub fn run_stub_scan(provider: &ContainerImageProvider) -> Vec<CheckReport> {
    let mut out = vec![];
    for meta in sample_checks() {
        out.push(CheckReport {
            check_id: meta.id.clone(),
            check_name: meta.name.clone(),
            status: Status::Unknown,
            status_extended: "stub: real implementation shells to trivy/grype".to_string(),
            severity: meta.severity.clone(),
            resource_id: provider.image_ref.clone(),
            resource_arn: format!("oci://{}", provider.image_ref),
            region: "local".to_string(),
            provider: "container-image".to_string(),
            service: meta.service.clone(),
            account_id: "local".to_string(),
            compliance: vec![ComplianceRef {
                framework: "nist_sp_800_190".to_string(),
                control_id: "tbd".to_string(),
            }],
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }
    out
}

fn meta(id: &str, service: &str, sev: Severity) -> CheckMetadata {
    CheckMetadata {
        id: id.to_string(),
        name: id.replace('_', " "),
        description: id.replace('_', " "),
        severity: sev,
        service: service.to_string(),
        provider: "container-image".to_string(),
        compliance: vec![ComplianceRef {
            framework: "nist_sp_800_190".to_string(),
            control_id: "tbd".to_string(),
        }],
    }
}
