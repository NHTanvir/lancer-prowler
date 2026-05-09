use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::storage::make_report;
use crate::providers::gcp::services::storage::GcpStorageService;

pub struct StorageBucketLabelEnvironment;

impl Check for StorageBucketLabelEnvironment {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_bucket_label_environment".to_string(),
            name: "Ensure that Cloud Storage buckets have an environment label".to_string(),
            description: "Labeling buckets with an environment tag (e.g. 'environment' or 'env') \
                helps with cost allocation, access control, and resource management across \
                development, staging, and production environments."
                .to_string(),
            severity: Severity::Low,
            service: "storage".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "GCP_WAF_2023".to_string(),
                    control_id: "OPS-4".to_string(),
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

            let has_env_label = bucket.labels.contains_key("environment")
                || bucket.labels.contains_key("env");

            let (status, msg) = if has_env_label {
                (
                    Status::Pass,
                    format!("Bucket {} has an environment label", bucket.name),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Bucket {} is missing an 'environment' or 'env' label",
                        bucket.name
                    ),
                )
            };

            reports.push(make_report(
                "storage_bucket_label_environment",
                "Ensure that Cloud Storage buckets have an environment label",
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
