//! Cloudflare provider (stub).
//!
//! Upstream v5.x ships 29 checks across 3 Cloudflare services. Real integration
//! uses the Cloudflare REST API with bearer tokens.

use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct CloudflareProvider {
    pub account_id: String,
}

impl CloudflareProvider {
    pub fn new_stub(account_id: String) -> Self {
        Self { account_id }
    }
}

impl Provider for CloudflareProvider {
    fn name(&self) -> &str { "Cloudflare" }
    fn provider_id(&self) -> &str { "cloudflare" }
    fn account_id(&self) -> &str { &self.account_id }
    fn regions(&self) -> Vec<String> { vec!["global".to_string()] }
}

pub const SERVICES: &[&str] = &["account", "zone", "access"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("account_2fa_required_for_members", "account", Severity::Critical),
        meta("account_audit_logs_retention_180_days", "account", Severity::Medium),
        meta("zone_dnssec_enabled", "zone", Severity::High),
        meta("zone_ssl_min_tls_1_2", "zone", Severity::High),
        meta("zone_waf_enabled", "zone", Severity::High),
        meta("access_session_max_duration_24h", "access", Severity::Medium),
    ]
}

pub fn run_stub_scan(provider: &CloudflareProvider) -> Vec<CheckReport> {
    let mut out = vec![];
    for meta in sample_checks() {
        out.push(CheckReport {
            check_id: meta.id.clone(),
            check_name: meta.name.clone(),
            status: Status::Unknown,
            status_extended: "stub: real Cloudflare integration uses Cloudflare REST API".to_string(),
            severity: meta.severity.clone(),
            resource_id: provider.account_id.clone(),
            resource_arn: format!("cloudflare://{}", provider.account_id),
            region: "global".to_string(),
            provider: "cloudflare".to_string(),
            service: meta.service.clone(),
            account_id: provider.account_id.clone(),
            compliance: vec![ComplianceRef {
                framework: "cis_cloudflare_benchmark_v1.0.0".to_string(),
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
        provider: "cloudflare".to_string(),
        compliance: vec![ComplianceRef {
            framework: "cis_cloudflare_benchmark_v1.0.0".to_string(),
            control_id: "tbd".to_string(),
        }],
    }
}

pub struct CloudflareStubCheck {
    pub metadata: CheckMetadata,
}

impl Check for CloudflareStubCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }
    fn execute(&self, _context: &dyn std::any::Any) -> Vec<CheckReport> {
        Vec::new()
    }
}
