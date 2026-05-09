use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::storage::make_report;
use crate::providers::gcp::services::storage::GcpStorageService;

pub struct StorageBucketUniformBucketLevelAccess;

impl Check for StorageBucketUniformBucketLevelAccess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_bucket_uniform_bucket_level_access".to_string(),
            name: "Ensure that Cloud Storage buckets have uniform bucket-level access enabled".to_string(),
            description: "Uniform bucket-level access enforces IAM-only access control and \
                disables legacy ACLs, providing a consistent and manageable access control model."
                .to_string(),
            severity: Severity::High,
            service: "storage".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "5.2".to_string(),
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

            let (status, msg) = if bucket.uniform_bucket_level_access {
                (
                    Status::Pass,
                    format!("Bucket {} has uniform bucket-level access enabled", bucket.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Bucket {} does not have uniform bucket-level access enabled", bucket.name),
                )
            };

            reports.push(make_report(
                "storage_bucket_uniform_bucket_level_access",
                "Ensure that Cloud Storage buckets have uniform bucket-level access enabled",
                Severity::High,
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
