//! Oracle Cloud Infrastructure (OCI) provider (stub).
//!
//! Upstream v5.x ships 51 checks across 14 OCI services. Real integration uses
//! the OCI REST APIs with HMAC signing.

use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct OciProvider {
    pub tenancy_id: String,
}

impl OciProvider {
    pub fn new_stub(tenancy_id: String) -> Self {
        Self { tenancy_id }
    }
}

impl Provider for OciProvider {
    fn name(&self) -> &str { "Oracle Cloud Infrastructure" }
    fn provider_id(&self) -> &str { "oci" }
    fn account_id(&self) -> &str { &self.tenancy_id }
    fn regions(&self) -> Vec<String> {
        vec![
            "us-ashburn-1".to_string(),
            "us-phoenix-1".to_string(),
            "eu-frankfurt-1".to_string(),
        ]
    }
}

pub const SERVICES: &[&str] = &[
    "identity",
    "audit",
    "objectstorage",
    "compute",
    "virtualnetwork",
    "vault",
    "logging",
    "loadbalancer",
    "databasedb",
    "filestorage",
    "blockstorage",
    "kms",
    "events",
    "notifications",
];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("identity_no_root_compartment_access", "identity", Severity::Critical),
        meta("identity_mfa_for_users_with_console_access", "identity", Severity::High),
        meta("objectstorage_bucket_not_public", "objectstorage", Severity::Critical),
        meta("compute_instance_no_public_ip", "compute", Severity::High),
        meta("audit_log_retention_365_days", "audit", Severity::Medium),
        meta("vault_secret_rotation_enabled", "vault", Severity::High),
    ]
}

pub fn run_stub_scan(provider: &OciProvider) -> Vec<CheckReport> {
    let mut out = vec![];
    for meta in sample_checks() {
        out.push(CheckReport {
            check_id: meta.id.clone(),
            check_name: meta.name.clone(),
            status: Status::Unknown,
            status_extended:
                "stub: real OCI integration uses OCI REST APIs + HMAC signing"
                    .to_string(),
            severity: meta.severity.clone(),
            resource_id: provider.tenancy_id.clone(),
            resource_arn: format!("ocid1.tenancy.oc1..{}", provider.tenancy_id),
            region: "us-ashburn-1".to_string(),
            provider: "oci".to_string(),
            service: meta.service.clone(),
            account_id: provider.tenancy_id.clone(),
            compliance: vec![ComplianceRef {
                framework: "cis_oci_benchmark_v2.0.0".to_string(),
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
        provider: "oci".to_string(),
        compliance: vec![ComplianceRef {
            framework: "cis_oci_benchmark_v2.0.0".to_string(),
            control_id: "tbd".to_string(),
        }],
    }
}

pub struct OciStubCheck {
    pub metadata: CheckMetadata,
}

impl Check for OciStubCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }
    fn execute(&self, _context: &dyn std::any::Any) -> Vec<CheckReport> {
        Vec::new()
    }
}
