use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::storage::make_report;
use crate::providers::gcp::services::storage::GcpStorageService;

pub struct StorageBucketLoggingEnabled;

impl Check for StorageBucketLoggingEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_bucket_logging_enabled".to_string(),
            name: "Ensure that logging is enabled for Cloud Storage buckets".to_string(),
            description: "Storage access logs capture all requests made to a bucket, providing \
                an audit trail for detecting unauthorized access patterns and forensic investigations."
                .to_string(),
            severity: Severity::Medium,
            service: "storage".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "5.4".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AU-2".to_string(),
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

            let (status, msg) = if bucket.logging_enabled {
                (
                    Status::Pass,
                    format!("Bucket {} has access logging enabled", bucket.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Bucket {} does not have access logging enabled", bucket.name),
                )
            };

            reports.push(make_report(
                "storage_bucket_logging_enabled",
                "Ensure that logging is enabled for Cloud Storage buckets",
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
