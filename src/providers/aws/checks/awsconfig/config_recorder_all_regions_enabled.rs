use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::awsconfig::make_report;
use crate::providers::aws::services::awsconfig::AwsConfigService;

pub struct ConfigRecorderAllRegionsEnabled;

impl Check for ConfigRecorderAllRegionsEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "config_recorder_all_regions_enabled".to_string(),
            name: "Ensure AWS Config is enabled in all regions".to_string(),
            description: "AWS Config tracks configuration changes to AWS resources. \
                A configuration recorder must exist and be recording in every region."
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

            let (status, msg) = if recorder.recording {
                (
                    Status::Pass,
                    format!(
                        "AWS Config recorder '{}' in region {} is active and recording",
                        recorder.name, recorder.region
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "AWS Config recorder '{}' in region {} exists but is not recording",
                        recorder.name, recorder.region
                    ),
                )
            };

            reports.push(make_report(
                "config_recorder_all_regions_enabled",
                "Ensure AWS Config is enabled in all regions",
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
