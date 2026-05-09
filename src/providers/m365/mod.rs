//! Microsoft 365 provider (stub).
//!
//! Upstream v5.x ships 102 checks across 10 M365 services (Teams, Defender,
//! Purview, Exchange, AdminCenter, Entra ID, SharePoint, OneDrive,
//! PowerBI, MicrosoftPurview). Real integration uses Microsoft Graph API via
//! REST + OAuth. Stubs return synthetic findings so the surface compiles.

use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct M365Provider {
    pub tenant_id: String,
}

impl M365Provider {
    pub fn new_stub(tenant_id: String) -> Self {
        Self { tenant_id }
    }
}

impl Provider for M365Provider {
    fn name(&self) -> &str { "Microsoft 365" }
    fn provider_id(&self) -> &str { "m365" }
    fn account_id(&self) -> &str { &self.tenant_id }
    fn regions(&self) -> Vec<String> { vec!["global".to_string()] }
}

pub const SERVICES: &[&str] = &[
    "teams",
    "defender",
    "purview",
    "exchange",
    "admincenter",
    "entra",
    "sharepoint",
    "onedrive",
    "powerbi",
    "intune",
];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("teams_external_access_restricted", "teams", Severity::Medium),
        meta("defender_safe_links_enabled", "defender", Severity::High),
        meta("entra_mfa_required_for_admins", "entra", Severity::Critical),
        meta("exchange_dkim_enabled", "exchange", Severity::High),
        meta("sharepoint_modern_authentication_only", "sharepoint", Severity::Medium),
        meta("onedrive_external_sharing_restricted", "onedrive", Severity::Medium),
        meta("purview_dlp_policies_enabled", "purview", Severity::High),
    ]
}

pub fn run_stub_scan(provider: &M365Provider) -> Vec<CheckReport> {
    let mut out = vec![];
    for meta in sample_checks() {
        out.push(CheckReport {
            check_id: meta.id.clone(),
            check_name: meta.name.clone(),
            status: Status::Unknown,
            status_extended: "stub: real M365 integration uses Microsoft Graph API".to_string(),
            severity: meta.severity.clone(),
            resource_id: provider.tenant_id.clone(),
            resource_arn: format!("m365://{}", provider.tenant_id),
            region: "global".to_string(),
            provider: "m365".to_string(),
            service: meta.service.clone(),
            account_id: provider.tenant_id.clone(),
            compliance: vec![ComplianceRef {
                framework: "cis_microsoft_365_foundations_v4.0.0".to_string(),
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
        provider: "m365".to_string(),
        compliance: vec![ComplianceRef {
            framework: "cis_microsoft_365_foundations_v4.0.0".to_string(),
            control_id: "tbd".to_string(),
        }],
    }
}

/// Trait-object friendly wrapper so this can be plugged into the `Check` trait.
pub struct M365StubCheck {
    pub metadata: CheckMetadata,
}

impl Check for M365StubCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }
    fn execute(&self, _context: &dyn std::any::Any) -> Vec<CheckReport> {
        Vec::new()
    }
}
