use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::storage::make_report;
use crate::providers::gcp::services::storage::GcpStorageService;

pub struct StorageBucketRetentionPolicy;

impl Check for StorageBucketRetentionPolicy {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_bucket_retention_policy".to_string(),
            name: "Ensure that Cloud Storage buckets have a locked retention policy".to_string(),
            description: "A locked retention policy prevents objects from being deleted or \
                replaced until the retention period expires. This is required for regulatory \
                compliance and ensures data immutability for audit logs."
                .to_string(),
            severity: Severity::Low,
            service: "storage".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "5.6".to_string(),
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

            let (status, msg) = if bucket.retention_policy_locked {
                (
                    Status::Pass,
                    format!("Bucket {} has a locked retention policy", bucket.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Bucket {} does not have a locked retention policy", bucket.name),
                )
            };

            reports.push(make_report(
                "storage_bucket_retention_policy",
                "Ensure that Cloud Storage buckets have a locked retention policy",
                Severity::Low,
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
