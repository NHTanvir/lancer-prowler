use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::s3::make_report;
use crate::providers::aws::services::s3::S3Service;

pub struct S3BucketServerAccessLoggingEnabled;

impl Check for S3BucketServerAccessLoggingEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "s3_bucket_server_access_logging_enabled".to_string(),
            name: "Ensure S3 bucket server access logging is enabled".to_string(),
            description: "S3 server access logging provides detailed records of requests made \
                to a bucket. Enabling logging helps detect security incidents and access patterns."
                .to_string(),
            severity: Severity::Low,
            service: "s3".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.6".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AU-2".to_string(),
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

            let (status, msg) = if bucket.logging_enabled {
                (
                    Status::Pass,
                    format!("Bucket {} has server access logging enabled", bucket.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Bucket {} does not have server access logging enabled", bucket.name),
                )
            };

            reports.push(make_report(
                "s3_bucket_server_access_logging_enabled",
                "Ensure S3 bucket server access logging is enabled",
                Severity::Low,
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
