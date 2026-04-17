use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::s3::make_report;
use crate::providers::aws::services::s3::S3Service;

pub struct S3BucketAclProhibited;

impl Check for S3BucketAclProhibited {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "s3_bucket_acl_prohibited".to_string(),
            name: "Ensure S3 bucket ACL is private".to_string(),
            description: "S3 bucket ACLs should be set to private. Public ACLs expose data \
                to anyone on the internet."
                .to_string(),
            severity: Severity::High,
            service: "s3".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.1.2".to_string(),
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

            let (status, msg) = if bucket.acl == "private" {
                (
                    Status::Pass,
                    format!("Bucket {} ACL is private", bucket.name),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Bucket {} has a non-private ACL: {}",
                        bucket.name, bucket.acl
                    ),
                )
            };

            reports.push(make_report(
                "s3_bucket_acl_prohibited",
                "Ensure S3 bucket ACL is private",
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
