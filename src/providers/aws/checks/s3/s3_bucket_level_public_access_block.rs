use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::s3::make_report;
use crate::providers::aws::services::s3::S3Service;

pub struct S3BucketLevelPublicAccessBlock;

impl Check for S3BucketLevelPublicAccessBlock {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "s3_bucket_level_public_access_block".to_string(),
            name: "Ensure S3 bucket-level public access block is fully configured".to_string(),
            description: "Each S3 bucket should have all four public access block settings \
                enabled to prevent unintended public exposure of bucket contents."
                .to_string(),
            severity: Severity::High,
            service: "s3".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.1.4".to_string(),
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

            let (status, msg) = match &bucket.public_access_block {
                None => (
                    Status::Fail,
                    format!(
                        "Bucket {} has no public access block configuration",
                        bucket.name
                    ),
                ),
                Some(pab) => {
                    if pab.block_public_acls
                        && pab.ignore_public_acls
                        && pab.block_public_policy
                        && pab.restrict_public_buckets
                    {
                        (
                            Status::Pass,
                            format!(
                                "Bucket {} has all four public access block settings enabled",
                                bucket.name
                            ),
                        )
                    } else {
                        (
                            Status::Fail,
                            format!(
                                "Bucket {} is missing some public access block settings \
                                (BlockPublicAcls={}, IgnorePublicAcls={}, \
                                BlockPublicPolicy={}, RestrictPublicBuckets={})",
                                bucket.name,
                                pab.block_public_acls,
                                pab.ignore_public_acls,
                                pab.block_public_policy,
                                pab.restrict_public_buckets,
                            ),
                        )
                    }
                }
            };

            reports.push(make_report(
                "s3_bucket_level_public_access_block",
                "Ensure S3 bucket-level public access block is fully configured",
                Severity::High,
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
