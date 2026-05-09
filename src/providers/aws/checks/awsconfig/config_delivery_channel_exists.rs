use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::awsconfig::make_report;
use crate::providers::aws::services::awsconfig::AwsConfigService;

pub struct ConfigDeliveryChannelExists;

impl Check for ConfigDeliveryChannelExists {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "config_delivery_channel_exists".to_string(),
            name: "Ensure AWS Config has a delivery channel configured".to_string(),
            description: "A delivery channel is required to deliver configuration snapshots \
                and history files to an S3 bucket and optionally SNS notifications. \
                Without a delivery channel, configuration data is not persisted."
                .to_string(),
            severity: Severity::Medium,
            service: "config".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.5".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "CM-8".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<AwsConfigService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for recorder in &svc.recorders {
            let resource_arn = format!(
                "arn:aws:config:{}:{}:configuration-recorder/{}",
                recorder.region, account_id, recorder.name
            );

            let (status, msg) = if recorder.delivery_channel_exists {
                (
                    Status::Pass,
                    format!(
                        "AWS Config recorder '{}' in region {} has a delivery channel configured",
                        recorder.name, recorder.region
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "AWS Config recorder '{}' in region {} has no delivery channel configured",
                        recorder.name, recorder.region
                    ),
                )
            };

            reports.push(make_report(
                "config_delivery_channel_exists",
                "Ensure AWS Config has a delivery channel configured",
                Severity::Medium,
                status,
                &recorder.name,
                &resource_arn,
                &recorder.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
