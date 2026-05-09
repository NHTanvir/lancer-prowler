//! StackIT (Schwarz Group cloud) provider (stub).

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct StackitProvider {
    pub project_id: String,
}

impl StackitProvider {
    pub fn new_stub(project_id: String) -> Self {
        Self { project_id }
    }
}

impl Provider for StackitProvider {
    fn name(&self) -> &str { "StackIT" }
    fn provider_id(&self) -> &str { "stackit" }
    fn account_id(&self) -> &str { &self.project_id }
    fn regions(&self) -> Vec<String> { vec!["eu01".into()] }
}

pub const SERVICES: &[&str] = &["iam", "object-storage", "ske", "postgresql"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("iam_no_inherited_owner", "iam", Severity::High),
        meta("object_storage_bucket_not_public", "object-storage", Severity::Critical),
        meta("ske_cluster_private_endpoint", "ske", Severity::High),
        meta("postgresql_encryption_at_rest", "postgresql", Severity::High),
    ]
}

pub fn run_stub_scan(p: &StackitProvider) -> Vec<CheckReport> {
    sample_checks().into_iter().map(|m| stub_report(p, m)).collect()
}

fn stub_report(p: &StackitProvider, m: CheckMetadata) -> CheckReport {
    CheckReport {
        check_id: m.id.clone(),
        check_name: m.name.clone(),
        status: Status::Unknown,
        status_extended: "stub: real StackIT integration uses the StackIT API".into(),
        severity: m.severity,
        resource_id: p.project_id.clone(),
        resource_arn: format!("stackit://{}", p.project_id),
        region: "eu01".into(),
        provider: "stackit".into(),
        service: m.service,
        account_id: p.project_id.clone(),
        compliance: m.compliance,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

fn meta(id: &str, service: &str, sev: Severity) -> CheckMetadata {
    CheckMetadata {
        id: id.into(),
        name: id.replace('_', " "),
        description: id.replace('_', " "),
        severity: sev,
        service: service.into(),
        provider: "stackit".into(),
        compliance: vec![ComplianceRef {
            framework: "bsi_c5".into(),
            control_id: "tbd".into(),
        }],
    }
}
