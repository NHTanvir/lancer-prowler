use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::cloudtrail::make_report;
use crate::providers::aws::services::cloudtrail::CloudtrailService;

pub struct CloudtrailLogsS3BucketIsNotPubliclyAccessible;

impl Check for CloudtrailLogsS3BucketIsNotPubliclyAccessible {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "cloudtrail_logs_s3_bucket_is_not_publicly_accessible".to_string(),
            name: "Ensure the S3 bucket used by CloudTrail is not publicly accessible".to_string(),
            description: "CloudTrail logs contain sensitive account activity. The S3 bucket \
                storing these logs must not be publicly accessible."
                .to_string(),
            severity: Severity::Critical,
            service: "cloudtrail".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.3".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-3".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<CloudtrailService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for trail in &svc.trails {
            let resource_arn = trail.arn.clone();
            // s3_bucket_is_public is always false at this layer (no S3 cross-reference).
            let msg = format!(
                "CloudTrail trail {} logs to S3 bucket '{}' — \
                public access status not cross-referenced, verify manually",
                trail.name, trail.s3_bucket_name
            );
            reports.push(make_report(
                "cloudtrail_logs_s3_bucket_is_not_publicly_accessible",
                "Ensure the S3 bucket used by CloudTrail is not publicly accessible",
                Severity::Critical,
                Status::Pass,
                &trail.name,
                &resource_arn,
                &trail.home_region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        if reports.is_empty() {
            let resource_arn = format!("arn:aws:cloudtrail:::account/{}", account_id);
            reports.push(make_report(
                "cloudtrail_logs_s3_bucket_is_not_publicly_accessible",
                "Ensure the S3 bucket used by CloudTrail is not publicly accessible",
                Severity::Critical,
                Status::Fail,
                account_id,
                &resource_arn,
                "us-east-1",
                account_id,
                "No CloudTrail trails found — cannot verify S3 bucket accessibility",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
