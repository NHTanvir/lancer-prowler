use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::s3::make_report;
use crate::providers::aws::services::s3::S3Service;

pub struct S3BucketKmsEncryption;

impl Check for S3BucketKmsEncryption {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "s3_bucket_kms_encryption".to_string(),
            name: "Ensure S3 bucket uses KMS-managed encryption (SSE-KMS)".to_string(),
            description: "S3 buckets should use SSE-KMS encryption with a customer-managed KMS \
                key for stronger control over encryption keys compared to SSE-S3."
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
                    format!("Bucket {} has no encryption configured", bucket.name),
                ),
                Some(enc) if !enc.enabled => (
                    Status::Fail,
                    format!("Bucket {} encryption is disabled", bucket.name),
                ),
                Some(enc) => match &enc.kms_master_key_id {
                    Some(key_id) => (
                        Status::Pass,
                        format!(
                            "Bucket {} uses SSE-KMS with key {}",
                            bucket.name, key_id
                        ),
                    ),
                    None => (
                        Status::Fail,
                        format!(
                            "Bucket {} uses SSE-S3 (AES256) — upgrade to SSE-KMS for stronger key management",
                            bucket.name
                        ),
                    ),
                },
            };

            reports.push(make_report(
                "s3_bucket_kms_encryption",
                "Ensure S3 bucket uses KMS-managed encryption (SSE-KMS)",
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
