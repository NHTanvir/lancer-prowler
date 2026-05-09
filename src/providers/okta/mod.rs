//! Okta provider (stub).

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct OktaProvider {
    pub org_url: String,
}

impl OktaProvider {
    pub fn new_stub(org_url: String) -> Self {
        Self { org_url }
    }
}

impl Provider for OktaProvider {
    fn name(&self) -> &str { "Okta" }
    fn provider_id(&self) -> &str { "okta" }
    fn account_id(&self) -> &str { &self.org_url }
    fn regions(&self) -> Vec<String> { vec!["global".to_string()] }
}

pub const SERVICES: &[&str] = &["users", "groups", "applications", "policies", "system_log"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("policy_mfa_factor_enrollment", "policies", Severity::Critical),
        meta("policy_password_min_length_14", "policies", Severity::High),
        meta("policy_session_lifetime", "policies", Severity::Medium),
        meta("users_admin_count_minimum", "users", Severity::High),
        meta("system_log_retention_90_days", "system_log", Severity::Medium),
    ]
}

pub fn run_stub_scan(p: &OktaProvider) -> Vec<CheckReport> {
    sample_checks().into_iter().map(|m| stub_report(p, m)).collect()
}

fn stub_report(p: &OktaProvider, m: CheckMetadata) -> CheckReport {
    CheckReport {
        check_id: m.id.clone(),
        check_name: m.name.clone(),
        status: Status::Unknown,
        status_extended: "stub: real Okta integration uses the Okta Management API".into(),
        severity: m.severity,
        resource_id: p.org_url.clone(),
        resource_arn: format!("okta://{}", p.org_url),
        region: "global".into(),
        provider: "okta".into(),
        service: m.service,
        account_id: p.org_url.clone(),
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
        provider: "okta".into(),
        compliance: vec![ComplianceRef {
            framework: "soc2".into(),
            control_id: "CC6.1".into(),
        }],
    }
}
