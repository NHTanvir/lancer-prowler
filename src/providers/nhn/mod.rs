//! NHN Cloud (Korean cloud provider) (stub).

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct NhnProvider {
    pub project_id: String,
}

impl NhnProvider {
    pub fn new_stub(project_id: String) -> Self {
        Self { project_id }
    }
}

impl Provider for NhnProvider {
    fn name(&self) -> &str { "NHN Cloud" }
    fn provider_id(&self) -> &str { "nhn" }
    fn account_id(&self) -> &str { &self.project_id }
    fn regions(&self) -> Vec<String> { vec!["KR1".into(), "JP1".into()] }
}

pub const SERVICES: &[&str] = &["iam", "object-storage", "instance", "network"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("iam_mfa_for_admins", "iam", Severity::Critical),
        meta("object_storage_bucket_not_public", "object-storage", Severity::Critical),
        meta("instance_no_public_ip_by_default", "instance", Severity::Medium),
        meta("network_secgroup_no_open_ingress", "network", Severity::High),
    ]
}

pub fn run_stub_scan(p: &NhnProvider) -> Vec<CheckReport> {
    sample_checks().into_iter().map(|m| stub_report(p, m)).collect()
}

fn stub_report(p: &NhnProvider, m: CheckMetadata) -> CheckReport {
    CheckReport {
        check_id: m.id.clone(),
        check_name: m.name.clone(),
        status: Status::Unknown,
        status_extended: "stub: real NHN integration uses the NHN Cloud OpenAPI".into(),
        severity: m.severity,
        resource_id: p.project_id.clone(),
        resource_arn: format!("nhn://{}", p.project_id),
        region: "KR1".into(),
        provider: "nhn".into(),
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
        provider: "nhn".into(),
        compliance: vec![ComplianceRef {
            framework: "kisa_isms_p".into(),
            control_id: "tbd".into(),
        }],
    }
}
