//! GitHub provider (stub).
//!
//! Upstream v5.x ships 24 checks across 3 GitHub services (repository,
//! workflow, organization). Real integration uses the GitHub REST/GraphQL API.

use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct GithubProvider {
    pub organization: String,
}

impl GithubProvider {
    pub fn new_stub(organization: String) -> Self {
        Self { organization }
    }
}

impl Provider for GithubProvider {
    fn name(&self) -> &str { "GitHub" }
    fn provider_id(&self) -> &str { "github" }
    fn account_id(&self) -> &str { &self.organization }
    fn regions(&self) -> Vec<String> { vec!["global".to_string()] }
}

pub const SERVICES: &[&str] = &["repository", "workflow", "organization"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("repository_branch_protection_main", "repository", Severity::High),
        meta("repository_default_branch_signed_commits", "repository", Severity::Medium),
        meta("workflow_no_hardcoded_secrets", "workflow", Severity::Critical),
        meta("workflow_actions_pinned_to_sha", "workflow", Severity::High),
        meta("organization_2fa_required", "organization", Severity::Critical),
        meta("organization_default_member_permission_least_privilege", "organization", Severity::Medium),
    ]
}

pub fn run_stub_scan(provider: &GithubProvider) -> Vec<CheckReport> {
    let mut out = vec![];
    for meta in sample_checks() {
        out.push(CheckReport {
            check_id: meta.id.clone(),
            check_name: meta.name.clone(),
            status: Status::Unknown,
            status_extended:
                "stub: real GitHub integration uses GitHub REST API + GraphQL API"
                    .to_string(),
            severity: meta.severity.clone(),
            resource_id: provider.organization.clone(),
            resource_arn: format!("github://{}", provider.organization),
            region: "global".to_string(),
            provider: "github".to_string(),
            service: meta.service.clone(),
            account_id: provider.organization.clone(),
            compliance: vec![ComplianceRef {
                framework: "cis_github_benchmark_v1.0.0".to_string(),
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
        provider: "github".to_string(),
        compliance: vec![ComplianceRef {
            framework: "cis_github_benchmark_v1.0.0".to_string(),
            control_id: "tbd".to_string(),
        }],
    }
}

pub struct GithubStubCheck {
    pub metadata: CheckMetadata,
}

impl Check for GithubStubCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }
    fn execute(&self, _context: &dyn std::any::Any) -> Vec<CheckReport> {
        Vec::new()
    }
}
