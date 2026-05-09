use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::s3::make_report;
use crate::providers::aws::services::s3::S3Service;

pub struct S3BucketDefaultEncryption;

impl Check for S3BucketDefaultEncryption {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "s3_bucket_default_encryption".to_string(),
            name: "Ensure S3 bucket has default encryption enabled".to_string(),
            description: "S3 bucket default encryption ensures that all objects are encrypted \
                at rest. SSE-S3 or SSE-KMS must be configured."
                .to_string(),
            severity: Severity::Medium,
            service: "s3".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.1.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-28".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<S3Service>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for bucket in &svc.buckets {
            let resource_arn = format!("arn:aws:s3:::{}", bucket.name);

            let (status, msg) = match &bucket.encryption {
                None => (
                    Status::Fail,
                    format!("Bucket {} does not have default encryption enabled", bucket.name),
                ),
                Some(enc) if !enc.enabled => (
                    Status::Fail,
                    format!("Bucket {} encryption is configured but not enabled", bucket.name),
                ),
                Some(_) => (
                    Status::Pass,
                    format!("Bucket {} has default encryption enabled", bucket.name),
                ),
            };

            reports.push(make_report(
                "s3_bucket_default_encryption",
                "Ensure S3 bucket has default encryption enabled",
                Severity::Medium,
                status,
                &bucket.name,
                &resource_arn,
                &bucket.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
