use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::securityhub::make_report;
use crate::providers::aws::services::securityhub::SecurityHubService;

pub struct SecurityHubEnabled;

impl Check for SecurityHubEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "securityhub_enabled".to_string(),
            name: "Ensure AWS Security Hub is enabled".to_string(),
            description: "AWS Security Hub provides a comprehensive view of security alerts \
                and security posture across AWS accounts. It should be enabled."
                .to_string(),
            severity: Severity::Medium,
            service: "securityhub".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_1.4".to_string(),
                    control_id: "3.10".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "RA-5".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<SecurityHubService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;

        if svc.hubs.is_empty() {
            vec![make_report(
                "securityhub_enabled",
                "Ensure AWS Security Hub is enabled",
                Severity::Medium,
                Status::Fail,
                account_id,
                "",
                "global",
                account_id,
                "AWS Security Hub is not enabled in any region",
                self.metadata().compliance.clone(),
            )]
        } else {
            vec![make_report(
                "securityhub_enabled",
                "Ensure AWS Security Hub is enabled",
                Severity::Medium,
                Status::Pass,
                account_id,
                "",
                "global",
                account_id,
                &format!(
                    "AWS Security Hub is enabled in {} region(s)",
                    svc.hubs.len()
                ),
                self.metadata().compliance.clone(),
            )]
        }
    }
}
