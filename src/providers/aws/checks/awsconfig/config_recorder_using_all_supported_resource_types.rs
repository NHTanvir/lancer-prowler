use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::awsconfig::make_report;
use crate::providers::aws::services::awsconfig::AwsConfigService;

pub struct ConfigRecorderUsingAllSupportedResourceTypes;

impl Check for ConfigRecorderUsingAllSupportedResourceTypes {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "config_recorder_using_all_supported_resource_types".to_string(),
            name: "Ensure AWS Config recorder captures all supported resource types".to_string(),
            description: "AWS Config should record all supported resource types to provide \
                complete visibility into configuration changes across your AWS environment."
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

            let (status, msg) = if recorder.all_supported {
                (
                    Status::Pass,
                    format!(
                        "AWS Config recorder '{}' in region {} records all supported resource types",
                        recorder.name, recorder.region
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "AWS Config recorder '{}' in region {} does not record all supported resource types",
                        recorder.name, recorder.region
                    ),
                )
            };

            reports.push(make_report(
                "config_recorder_using_all_supported_resource_types",
                "Ensure AWS Config recorder captures all supported resource types",
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
