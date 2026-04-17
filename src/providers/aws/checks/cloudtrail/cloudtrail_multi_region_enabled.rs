use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::cloudtrail::make_report;
use crate::providers::aws::services::cloudtrail::CloudtrailService;

pub struct CloudtrailMultiRegionEnabled;

impl Check for CloudtrailMultiRegionEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "cloudtrail_multi_region_enabled".to_string(),
            name: "Ensure CloudTrail is enabled in all regions".to_string(),
            description: "AWS CloudTrail should have at least one multi-region trail that is \
                actively logging. This ensures API activity is captured across all regions."
                .to_string(),
            severity: Severity::High,
            service: "cloudtrail".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AU-2".to_string(),
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
        let resource_arn = format!("arn:aws:cloudtrail:::account/{}", account_id);

        let has_multi_region_logging = svc
            .trails
            .iter()
            .any(|t| t.is_multi_region && t.is_logging);

        let (status, msg) = if has_multi_region_logging {
            (
                Status::Pass,
                "At least one multi-region CloudTrail trail is enabled and logging".to_string(),
            )
        } else {
            (
                Status::Fail,
                "No multi-region CloudTrail trail found that is actively logging".to_string(),
            )
        };

        vec![make_report(
            "cloudtrail_multi_region_enabled",
            "Ensure CloudTrail is enabled in all regions",
            Severity::High,
            status,
            account_id,
            &resource_arn,
            "us-east-1",
            account_id,
            &msg,
            self.metadata().compliance.clone(),
        )]
    }
}
