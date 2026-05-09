//! MongoDB Atlas provider (stub).

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct MongoDbAtlasProvider {
    pub org_id: String,
}

impl MongoDbAtlasProvider {
    pub fn new_stub(org_id: String) -> Self {
        Self { org_id }
    }
}

impl Provider for MongoDbAtlasProvider {
    fn name(&self) -> &str { "MongoDB Atlas" }
    fn provider_id(&self) -> &str { "mongodb-atlas" }
    fn account_id(&self) -> &str { &self.org_id }
    fn regions(&self) -> Vec<String> { vec!["global".to_string()] }
}

pub const SERVICES: &[&str] = &["organization", "project", "cluster", "database"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("cluster_encryption_at_rest", "cluster", Severity::High),
        meta("cluster_ip_access_list_no_wildcard", "cluster", Severity::Critical),
        meta("project_mfa_required", "project", Severity::Critical),
        meta("database_audit_log_enabled", "database", Severity::Medium),
    ]
}

pub fn run_stub_scan(p: &MongoDbAtlasProvider) -> Vec<CheckReport> {
    sample_checks().into_iter().map(|m| stub_report(p, m)).collect()
}

fn stub_report(p: &MongoDbAtlasProvider, m: CheckMetadata) -> CheckReport {
    CheckReport {
        check_id: m.id.clone(),
        check_name: m.name.clone(),
        status: Status::Unknown,
        status_extended: "stub: real MongoDB Atlas integration uses the Atlas Admin API".into(),
        severity: m.severity,
        resource_id: p.org_id.clone(),
        resource_arn: format!("mongodb-atlas://{}", p.org_id),
        region: "global".into(),
        provider: "mongodb-atlas".into(),
        service: m.service,
        account_id: p.org_id.clone(),
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
        provider: "mongodb-atlas".into(),
        compliance: vec![ComplianceRef {
            framework: "soc2".into(),
            control_id: "CC6.1".into(),
        }],
    }
}
