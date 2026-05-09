use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::storage::make_report;
use crate::providers::gcp::services::storage::GcpStorageService;

pub struct StorageBucketPublicAccessPrevention;

impl Check for StorageBucketPublicAccessPrevention {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_bucket_public_access_prevention".to_string(),
            name: "Ensure that Cloud Storage buckets have public access prevention enforced".to_string(),
            description: "Public access prevention blocks public access to buckets and objects \
                regardless of how they are configured. Setting it to 'enforced' prevents \
                accidental public exposure of data."
                .to_string(),
            severity: Severity::Critical,
            service: "storage".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "5.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-3".to_string(),
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

            let (status, msg) = if bucket.public_access_prevention == "enforced" {
                (
                    Status::Pass,
                    format!("Bucket {} has public access prevention enforced", bucket.name),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Bucket {} has public access prevention set to '{}' instead of 'enforced'",
                        bucket.name, bucket.public_access_prevention
                    ),
                )
            };

            reports.push(make_report(
                "storage_bucket_public_access_prevention",
                "Ensure that Cloud Storage buckets have public access prevention enforced",
                Severity::Critical,
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
