use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::s3::make_report;
use crate::providers::aws::services::s3::S3Service;

pub struct S3BucketCrossAccountAccess;

impl Check for S3BucketCrossAccountAccess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "s3_bucket_cross_account_access".to_string(),
            name: "Ensure S3 bucket policy does not allow public (wildcard principal) access".to_string(),
            description: "S3 bucket policies with Effect:Allow and Principal:* grant access to \
                anyone on the internet. Verify that bucket policies do not include such \
                unrestricted principal grants."
                .to_string(),
            severity: Severity::Critical,
            service: "s3".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.1.5".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-3".to_string(),
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

            let (status, msg) = if bucket.policy_is_public {
                (
                    Status::Fail,
                    format!(
                        "Bucket {} has a bucket policy with Effect:Allow and Principal:* \
                        (public access granted)",
                        bucket.name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Bucket {} does not have a public wildcard principal in its bucket policy",
                        bucket.name
                    ),
                )
            };

            reports.push(make_report(
                "s3_bucket_cross_account_access",
                "Ensure S3 bucket policy does not allow public (wildcard principal) access",
                Severity::Critical,
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
