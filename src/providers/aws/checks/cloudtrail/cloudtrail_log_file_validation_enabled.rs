use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::cloudtrail::make_report;
use crate::providers::aws::services::cloudtrail::CloudtrailService;

pub struct CloudtrailLogFileValidationEnabled;

impl Check for CloudtrailLogFileValidationEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "cloudtrail_log_file_validation_enabled".to_string(),
            name: "Ensure CloudTrail log file validation is enabled".to_string(),
            description: "Log file validation creates a digitally signed digest file of each \
                CloudTrail log, allowing detection of log tampering."
                .to_string(),
            severity: Severity::Medium,
            service: "cloudtrail".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.2".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AU-9".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<CloudtrailService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for trail in &svc.trails {
            let resource_arn = trail.arn.clone();
            let (status, msg) = if trail.log_file_validation_enabled {
                (
                    Status::Pass,
                    format!("Trail {} has log file validation enabled", trail.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Trail {} does not have log file validation enabled", trail.name),
                )
            };

            reports.push(make_report(
                "cloudtrail_log_file_validation_enabled",
                "Ensure CloudTrail log file validation is enabled",
                Severity::Medium,
                status,
                &trail.name,
                &resource_arn,
                &trail.home_region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
