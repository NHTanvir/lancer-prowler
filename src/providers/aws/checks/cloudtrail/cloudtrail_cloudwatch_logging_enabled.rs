use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::cloudtrail::make_report;
use crate::providers::aws::services::cloudtrail::CloudtrailService;

pub struct CloudtrailCloudwatchLoggingEnabled;

impl Check for CloudtrailCloudwatchLoggingEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "cloudtrail_cloudwatch_logging_enabled".to_string(),
            name: "Ensure CloudTrail trails are integrated with CloudWatch Logs".to_string(),
            description: "Sending CloudTrail events to CloudWatch Logs enables real-time \
                monitoring, alerting, and metric filtering on API activity."
                .to_string(),
            severity: Severity::Medium,
            service: "cloudtrail".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.4".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AU-6".to_string(),
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
            let (status, msg) = match &trail.cloudwatch_logs_log_group_arn {
                Some(arn) => (
                    Status::Pass,
                    format!(
                        "Trail {} is integrated with CloudWatch Logs group {}",
                        trail.name, arn
                    ),
                ),
                None => (
                    Status::Fail,
                    format!(
                        "Trail {} is not integrated with CloudWatch Logs",
                        trail.name
                    ),
                ),
            };

            reports.push(make_report(
                "cloudtrail_cloudwatch_logging_enabled",
                "Ensure CloudTrail trails are integrated with CloudWatch Logs",
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
