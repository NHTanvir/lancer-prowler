use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::storage::make_report;
use crate::providers::gcp::services::storage::GcpStorageService;

pub struct StorageBucketVersioningEnabled;

impl Check for StorageBucketVersioningEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_bucket_versioning_enabled".to_string(),
            name: "Ensure that versioning is enabled for Cloud Storage buckets".to_string(),
            description: "Object versioning retains a history of objects so you can recover \
                from unintended deletion or overwrite. It is recommended for all buckets \
                containing sensitive or important data."
                .to_string(),
            severity: Severity::Medium,
            service: "storage".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "5.3".to_string(),
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
                "storage_bucket_versioning_enabled",
                "Ensure that versioning is enabled for Cloud Storage buckets",
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
