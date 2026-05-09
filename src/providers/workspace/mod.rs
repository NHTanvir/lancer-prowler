//! Google Workspace provider (stub).

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct WorkspaceProvider {
    pub customer_id: String,
}

impl WorkspaceProvider {
    pub fn new_stub(customer_id: String) -> Self {
        Self { customer_id }
    }
}

impl Provider for WorkspaceProvider {
    fn name(&self) -> &str { "Google Workspace" }
    fn provider_id(&self) -> &str { "workspace" }
    fn account_id(&self) -> &str { &self.customer_id }
    fn regions(&self) -> Vec<String> { vec!["global".to_string()] }
}

pub const SERVICES: &[&str] = &["admin", "drive", "gmail", "calendar"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("admin_2sv_required_for_admins", "admin", Severity::Critical),
        meta("drive_external_sharing_restricted", "drive", Severity::High),
        meta("gmail_dkim_enabled", "gmail", Severity::High),
        meta("gmail_dmarc_reject", "gmail", Severity::High),
    ]
}

pub fn run_stub_scan(p: &WorkspaceProvider) -> Vec<CheckReport> {
    sample_checks().into_iter().map(|m| stub_report(p, m)).collect()
}

fn stub_report(p: &WorkspaceProvider, m: CheckMetadata) -> CheckReport {
    CheckReport {
        check_id: m.id.clone(),
        check_name: m.name.clone(),
        status: Status::Unknown,
        status_extended: "stub: real Workspace integration uses the Google Admin SDK".into(),
        severity: m.severity,
        resource_id: p.customer_id.clone(),
        resource_arn: format!("workspace://{}", p.customer_id),
        region: "global".into(),
        provider: "workspace".into(),
        service: m.service,
        account_id: p.customer_id.clone(),
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
        provider: "workspace".into(),
        compliance: vec![ComplianceRef {
            framework: "cis_google_workspace".into(),
            control_id: "tbd".into(),
        }],
    }
}
