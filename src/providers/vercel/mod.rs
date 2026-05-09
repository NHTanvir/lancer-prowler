//! Vercel provider (stub).

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct VercelProvider {
    pub team_id: String,
}

impl VercelProvider {
    pub fn new_stub(team_id: String) -> Self {
        Self { team_id }
    }
}

impl Provider for VercelProvider {
    fn name(&self) -> &str { "Vercel" }
    fn provider_id(&self) -> &str { "vercel" }
    fn account_id(&self) -> &str { &self.team_id }
    fn regions(&self) -> Vec<String> { vec!["global".to_string()] }
}

pub const SERVICES: &[&str] = &["team", "project", "deployment", "secrets"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("team_2fa_required", "team", Severity::Critical),
        meta("project_environment_variables_encrypted", "project", Severity::High),
        meta("deployment_protection_enabled", "deployment", Severity::Medium),
        meta("secrets_no_committed_in_repo", "secrets", Severity::Critical),
    ]
}

pub fn run_stub_scan(p: &VercelProvider) -> Vec<CheckReport> {
    sample_checks().into_iter().map(|m| stub_report(p, m)).collect()
}

fn stub_report(p: &VercelProvider, m: CheckMetadata) -> CheckReport {
    CheckReport {
        check_id: m.id.clone(),
        check_name: m.name.clone(),
        status: Status::Unknown,
        status_extended: "stub: real Vercel integration uses the Vercel REST API".into(),
        severity: m.severity,
        resource_id: p.team_id.clone(),
        resource_arn: format!("vercel://{}", p.team_id),
        region: "global".into(),
        provider: "vercel".into(),
        service: m.service,
        account_id: p.team_id.clone(),
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
        provider: "vercel".into(),
        compliance: vec![ComplianceRef {
            framework: "soc2".into(),
            control_id: "CC6.1".into(),
        }],
    }
}
