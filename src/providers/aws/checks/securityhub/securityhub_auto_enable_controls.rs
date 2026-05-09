use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::securityhub::make_report;
use crate::providers::aws::services::securityhub::SecurityHubService;

pub struct SecurityHubAutoEnableControls;

impl Check for SecurityHubAutoEnableControls {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "securityhub_auto_enable_controls".to_string(),
            name: "Ensure Security Hub auto-enable controls is enabled".to_string(),
            description: "Security Hub auto-enable controls ensures that new security \
                controls are automatically enabled as they become available, keeping \
                your security posture up to date."
                .to_string(),
            severity: Severity::Low,
            service: "securityhub".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SI-2".to_string(),
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
        let mut reports = Vec::new();

        for hub in &svc.hubs {
            let (status, msg) = if !hub.auto_enable_controls {
                (
                    Status::Fail,
                    format!(
                        "Security Hub in region {} does not have auto-enable controls enabled",
                        hub.region
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Security Hub in region {} has auto-enable controls enabled",
                        hub.region
                    ),
                )
            };

            reports.push(make_report(
                "securityhub_auto_enable_controls",
                "Ensure Security Hub auto-enable controls is enabled",
                Severity::Low,
                status,
                &hub.hub_arn,
                &hub.hub_arn,
                &hub.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
