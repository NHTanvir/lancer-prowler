use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::cloudtrail::make_report;
use crate::providers::aws::services::cloudtrail::CloudtrailService;

pub struct CloudtrailS3DataeventsWriteEnabled;

impl Check for CloudtrailS3DataeventsWriteEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "cloudtrail_s3_dataevents_write_enabled".to_string(),
            name: "Ensure CloudTrail S3 data event logging is enabled for write events"
                .to_string(),
            description: "CloudTrail S3 data event logging captures object-level API activity \
                for S3. Enabling write events helps detect unauthorized modifications or deletions."
                .to_string(),
            severity: Severity::Medium,
            service: "cloudtrail".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.11".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AU-12".to_string(),
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
        let resource_arn = format!("arn:aws:cloudtrail:::account/{}", account_id);

        let has_s3_write = svc.trails.iter().any(|t| t.data_events_s3_write);

        let (status, msg) = if has_s3_write {
            (
                Status::Pass,
                "At least one CloudTrail trail has S3 write data events enabled".to_string(),
            )
        } else {
            (
                Status::Fail,
                "No CloudTrail trail has S3 write data events enabled".to_string(),
            )
        };

        vec![make_report(
            "cloudtrail_s3_dataevents_write_enabled",
            "Ensure CloudTrail S3 data event logging is enabled for write events",
            Severity::Medium,
            status,
            account_id,
            &resource_arn,
            "us-east-1",
            account_id,
            &msg,
            self.metadata().compliance.clone(),
        )]
    }
}
