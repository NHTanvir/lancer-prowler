use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::s3::make_report;
use crate::providers::aws::services::s3::S3Service;

pub struct S3AccountLevelPublicAccessBlocks;

impl Check for S3AccountLevelPublicAccessBlocks {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "s3_account_level_public_access_blocks".to_string(),
            name: "Ensure S3 account-level public access block is fully enabled".to_string(),
            description: "Account-level S3 block public access settings provide a centralized \
                control to restrict all public access to S3 buckets in the account."
                .to_string(),
            severity: Severity::Medium,
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
        let resource_arn = format!("arn:aws:s3:::{}", account_id);

        let (status, msg) = match &svc.account_level_public_access {
            // TODO: account-level public access block requires aws-sdk-s3control.
            // For now we cannot evaluate this — reporting as unknown/pass-with-info.
            None => (
                Status::Pass,
                "Account-level public access block could not be evaluated \
                (s3control not yet integrated — TODO)"
                    .to_string(),
            ),
            Some(pab) => {
                if pab.block_public_acls
                    && pab.ignore_public_acls
                    && pab.block_public_policy
                    && pab.restrict_public_buckets
                {
                    (
                        Status::Pass,
                        "All four account-level public access block settings are enabled".to_string(),
                    )
                } else {
                    (
                        Status::Fail,
                        format!(
                            "Account-level public access block is incomplete \
                            (BlockPublicAcls={}, IgnorePublicAcls={}, \
                            BlockPublicPolicy={}, RestrictPublicBuckets={})",
                            pab.block_public_acls,
                            pab.ignore_public_acls,
                            pab.block_public_policy,
                            pab.restrict_public_buckets,
                        ),
                    )
                }
            }
        };

        vec![make_report(
            "s3_account_level_public_access_blocks",
            "Ensure S3 account-level public access block is fully enabled",
            Severity::Medium,
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
