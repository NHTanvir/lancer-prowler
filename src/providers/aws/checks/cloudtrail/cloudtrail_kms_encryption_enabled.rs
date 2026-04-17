use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::cloudtrail::make_report;
use crate::providers::aws::services::cloudtrail::CloudtrailService;

pub struct CloudtrailKmsEncryptionEnabled;

impl Check for CloudtrailKmsEncryptionEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "cloudtrail_kms_encryption_enabled".to_string(),
            name: "Ensure CloudTrail logs are encrypted at rest using KMS".to_string(),
            description: "CloudTrail logs should be encrypted using a KMS customer-managed key \
                to provide an additional layer of security for sensitive audit data."
                .to_string(),
            severity: Severity::Medium,
            service: "cloudtrail".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.7".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-28".to_string(),
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
            let (status, msg) = match &trail.kms_key_id {
                Some(key_id) => (
                    Status::Pass,
                    format!(
                        "Trail {} is encrypted with KMS key {}",
                        trail.name, key_id
                    ),
                ),
                None => (
                    Status::Fail,
                    format!(
                        "Trail {} is not encrypted with a KMS key",
                        trail.name
                    ),
                ),
            };

            reports.push(make_report(
                "cloudtrail_kms_encryption_enabled",
                "Ensure CloudTrail logs are encrypted at rest using KMS",
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
