use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::s3::make_report;
use crate::providers::aws::services::s3::S3Service;

pub struct S3BucketSecureTransportPolicy;

impl Check for S3BucketSecureTransportPolicy {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "s3_bucket_secure_transport_policy".to_string(),
            name: "Ensure S3 bucket enforces HTTPS via a secure transport policy".to_string(),
            description: "S3 buckets should have a bucket policy that denies HTTP access \
                (aws:SecureTransport: false) to ensure all data in transit is encrypted."
                .to_string(),
            severity: Severity::Medium,
            service: "s3".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.1.3".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-8".to_string(),
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

            let (status, msg) = if bucket.secure_transport_policy {
                (
                    Status::Pass,
                    format!(
                        "Bucket {} has a policy enforcing secure transport (HTTPS)",
                        bucket.name
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Bucket {} does not enforce HTTPS — no Deny+aws:SecureTransport=false policy found",
                        bucket.name
                    ),
                )
            };

            reports.push(make_report(
                "s3_bucket_secure_transport_policy",
                "Ensure S3 bucket enforces HTTPS via a secure transport policy",
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
