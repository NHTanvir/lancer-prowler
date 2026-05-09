use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::s3::make_report;
use crate::providers::aws::services::s3::S3Service;

pub struct S3BucketObjectVersioning;

impl Check for S3BucketObjectVersioning {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "s3_bucket_object_versioning".to_string(),
            name: "Ensure S3 bucket versioning is enabled".to_string(),
            description: "S3 object versioning keeps multiple variants of an object in the same \
                bucket, protecting against accidental deletion and enabling recovery of previous \
                versions."
                .to_string(),
            severity: Severity::Low,
            service: "s3".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SI-12".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "CP-9".to_string(),
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

            let (status, msg) = if bucket.versioning_enabled {
                (
                    Status::Pass,
                    format!("Bucket {} has versioning enabled", bucket.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Bucket {} does not have versioning enabled", bucket.name),
                )
            };

            reports.push(make_report(
                "s3_bucket_object_versioning",
                "Ensure S3 bucket versioning is enabled",
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
