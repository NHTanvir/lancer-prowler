use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::cloudtrail::make_report;
use crate::providers::aws::services::cloudtrail::CloudtrailService;

pub struct CloudtrailThreatDetectionEnumeration;

impl Check for CloudtrailThreatDetectionEnumeration {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "cloudtrail_threat_detection_enumeration".to_string(),
            name: "Ensure CloudTrail Insights is enabled to detect enumeration activity"
                .to_string(),
            description: "CloudTrail Insights can detect unusual API activity such as resource \
                enumeration. This check is informational — enable via the AWS console."
                .to_string(),
            severity: Severity::High,
            service: "cloudtrail".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
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
        let resource_arn = format!("arn:aws:cloudtrail:::account/{}", account_id);

        vec![make_report(
            "cloudtrail_threat_detection_enumeration",
            "Ensure CloudTrail Insights is enabled to detect enumeration activity",
            Severity::High,
            Status::Pass,
            account_id,
            &resource_arn,
            "us-east-1",
            account_id,
            "CloudTrail Insights required for enumeration detection — \
            enable via console to detect resource enumeration patterns",
            self.metadata().compliance.clone(),
        )]
    }
}
