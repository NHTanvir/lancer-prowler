use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::storage::make_report;
use crate::providers::gcp::services::storage::GcpStorageService;

pub struct StorageBucketKmsEncryption;

impl Check for StorageBucketKmsEncryption {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_bucket_kms_encryption".to_string(),
            name: "Ensure that Cloud Storage buckets are encrypted with customer-managed keys".to_string(),
            description: "Using customer-managed encryption keys (CMEK) via Cloud KMS gives \
                you greater control over the lifecycle of your encryption keys and allows \
                you to meet compliance requirements for data residency and key management."
                .to_string(),
            severity: Severity::Medium,
            service: "storage".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "5.5".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-28".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<GcpStorageService>() {
            Some(s) => s,
            None => return vec![],
        };

        let mut reports = Vec::new();

        for bucket in &svc.buckets {
            let resource_arn = format!(
                "//storage.googleapis.com/projects/{}/buckets/{}",
                svc.project_id, bucket.name
            );

            let (status, msg) = match &bucket.kms_key_name {
                Some(key) => (
                    Status::Pass,
                    format!("Bucket {} is encrypted with KMS key {}", bucket.name, key),
                ),
                None => (
                    Status::Fail,
                    format!(
                        "Bucket {} is not encrypted with a customer-managed KMS key",
                        bucket.name
                    ),
                ),
            };

            reports.push(make_report(
                "storage_bucket_kms_encryption",
                "Ensure that Cloud Storage buckets are encrypted with customer-managed keys",
                Severity::Medium,
                status,
                &bucket.name,
                &resource_arn,
                &bucket.location,
                &svc.project_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
