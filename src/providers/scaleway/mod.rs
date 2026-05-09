//! Scaleway provider (stub).

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct ScalewayProvider {
    pub organization_id: String,
}

impl ScalewayProvider {
    pub fn new_stub(organization_id: String) -> Self {
        Self { organization_id }
    }
}

impl Provider for ScalewayProvider {
    fn name(&self) -> &str { "Scaleway" }
    fn provider_id(&self) -> &str { "scaleway" }
    fn account_id(&self) -> &str { &self.organization_id }
    fn regions(&self) -> Vec<String> { vec!["fr-par".into(), "nl-ams".into(), "pl-waw".into()] }
}

pub const SERVICES: &[&str] = &["iam", "object-storage", "instance", "lb", "rdb"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("iam_mfa_for_users", "iam", Severity::Critical),
        meta("object_storage_bucket_not_public", "object-storage", Severity::Critical),
        meta("instance_no_public_gateway_ip", "instance", Severity::Medium),
        meta("rdb_encrypted_at_rest", "rdb", Severity::High),
        meta("lb_redirect_http_to_https", "lb", Severity::Medium),
    ]
}

pub fn run_stub_scan(p: &ScalewayProvider) -> Vec<CheckReport> {
    sample_checks().into_iter().map(|m| stub_report(p, m)).collect()
}

fn stub_report(p: &ScalewayProvider, m: CheckMetadata) -> CheckReport {
    CheckReport {
        check_id: m.id.clone(),
        check_name: m.name.clone(),
        status: Status::Unknown,
        status_extended: "stub: real Scaleway integration uses the Scaleway API".into(),
        severity: m.severity,
        resource_id: p.organization_id.clone(),
        resource_arn: format!("scaleway://{}", p.organization_id),
        region: "fr-par".into(),
        provider: "scaleway".into(),
        service: m.service,
        account_id: p.organization_id.clone(),
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
        provider: "scaleway".into(),
        compliance: vec![ComplianceRef {
            framework: "secnumcloud".into(),
            control_id: "tbd".into(),
        }],
    }
}
