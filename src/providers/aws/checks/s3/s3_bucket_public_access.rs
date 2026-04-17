use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::s3::make_report;
use crate::providers::aws::services::s3::S3Service;

pub struct S3BucketPublicAccess;

impl Check for S3BucketPublicAccess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "s3_bucket_public_access".to_string(),
            name: "Ensure S3 bucket has block public policy and block public ACLs enabled".to_string(),
            description: "S3 bucket-level public access block settings should block public \
                policies and ACLs to prevent accidental data exposure."
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
                    if pab.block_public_policy && pab.block_public_acls {
                        (
                            Status::Pass,
                            format!(
                                "Bucket {} blocks public policies and ACLs",
                                bucket.name
                            ),
                        )
                    } else {
                        (
                            Status::Fail,
                            format!(
                                "Bucket {} does not fully block public access \
                                (BlockPublicPolicy={}, BlockPublicAcls={})",
                                bucket.name, pab.block_public_policy, pab.block_public_acls
                            ),
                        )
                    }
                }
            };

            reports.push(make_report(
                "s3_bucket_public_access",
                "Ensure S3 bucket has block public policy and block public ACLs enabled",
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
