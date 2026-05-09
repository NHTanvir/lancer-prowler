use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::storage::make_report;
use crate::providers::gcp::services::storage::GcpStorageService;

pub struct StorageBucketNotPubliclyAccessible;

impl Check for StorageBucketNotPubliclyAccessible {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_bucket_not_publicly_accessible".to_string(),
            name: "Ensure that Cloud Storage buckets are not publicly accessible".to_string(),
            description: "Buckets that are publicly accessible can expose sensitive data to \
                the internet. Public access prevention should be enforced to prevent \
                accidental or intentional public exposure."
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
                    format!("Bucket {} is not publicly accessible (public access prevention enforced)", bucket.name),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Bucket {} may be publicly accessible (public access prevention is '{}')",
                        bucket.name, bucket.public_access_prevention
                    ),
                )
            };

            reports.push(make_report(
                "storage_bucket_not_publicly_accessible",
                "Ensure that Cloud Storage buckets are not publicly accessible",
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
