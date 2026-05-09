//! Alibaba Cloud provider (stub).
//!
//! Upstream v5.x ships 63 checks across 9 Alibaba services. Real integration
//! uses the Alibaba Cloud OpenAPI gateway.

use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct AlibabaProvider {
    pub account_id: String,
}

impl AlibabaProvider {
    pub fn new_stub(account_id: String) -> Self {
        Self { account_id }
    }
}

impl Provider for AlibabaProvider {
    fn name(&self) -> &str { "Alibaba Cloud" }
    fn provider_id(&self) -> &str { "alibaba" }
    fn account_id(&self) -> &str { &self.account_id }
    fn regions(&self) -> Vec<String> {
        vec![
            "cn-hangzhou".to_string(),
            "cn-beijing".to_string(),
            "ap-southeast-1".to_string(),
        ]
    }
}

pub const SERVICES: &[&str] = &[
    "ram",
    "oss",
    "ecs",
    "vpc",
    "rds",
    "actiontrail",
    "kms",
    "cloudmonitor",
    "config",
];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("ram_no_root_access_key", "ram", Severity::Critical),
        meta("ram_mfa_for_users_with_console", "ram", Severity::High),
        meta("oss_bucket_not_public", "oss", Severity::Critical),
        meta("oss_bucket_server_side_encryption", "oss", Severity::High),
        meta("ecs_security_group_no_open_ingress", "ecs", Severity::High),
        meta("actiontrail_enabled_all_regions", "actiontrail", Severity::High),
    ]
}

pub fn run_stub_scan(provider: &AlibabaProvider) -> Vec<CheckReport> {
    let mut out = vec![];
    for meta in sample_checks() {
        out.push(CheckReport {
            check_id: meta.id.clone(),
            check_name: meta.name.clone(),
            status: Status::Unknown,
            status_extended:
                "stub: real Alibaba integration uses Alibaba Cloud OpenAPI"
                    .to_string(),
            severity: meta.severity.clone(),
            resource_id: provider.account_id.clone(),
            resource_arn: format!("acs:ram::{}", provider.account_id),
            region: "cn-hangzhou".to_string(),
            provider: "alibaba".to_string(),
            service: meta.service.clone(),
            account_id: provider.account_id.clone(),
            compliance: vec![ComplianceRef {
                framework: "cis_alibaba_cloud_benchmark_v1.0.0".to_string(),
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
        provider: "alibaba".to_string(),
        compliance: vec![ComplianceRef {
            framework: "cis_alibaba_cloud_benchmark_v1.0.0".to_string(),
            control_id: "tbd".to_string(),
        }],
    }
}

pub struct AlibabaStubCheck {
    pub metadata: CheckMetadata,
}

impl Check for AlibabaStubCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }
    fn execute(&self, _context: &dyn std::any::Any) -> Vec<CheckReport> {
        Vec::new()
    }
}
