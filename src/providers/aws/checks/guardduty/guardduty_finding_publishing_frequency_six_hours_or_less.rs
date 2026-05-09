use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::guardduty::make_report;
use crate::providers::aws::services::guardduty::GuardDutyService;

pub struct GuardDutyFindingPublishingFrequencySixHoursOrLess;

impl Check for GuardDutyFindingPublishingFrequencySixHoursOrLess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "guardduty_finding_publishing_frequency_six_hours_or_less".to_string(),
            name: "Ensure GuardDuty finding publishing frequency is not set to SIX_HOURS".to_string(),
            description: "GuardDuty can publish findings to CloudWatch Events and S3. \
                The frequency should be FIFTEEN_MINUTES or ONE_HOUR for timely alerting, \
                not SIX_HOURS which delays incident response."
                .to_string(),
            severity: Severity::Low,
            service: "guardduty".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SI-4".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<GuardDutyService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for detector in svc.detectors.iter().filter(|d| d.status == "ENABLED") {
            let (status, msg) = if detector.finding_publishing_frequency == "SIX_HOURS" {
                (
                    Status::Fail,
                    format!(
                        "GuardDuty detector {} has finding publishing frequency set to SIX_HOURS",
                        detector.detector_id
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "GuardDuty detector {} finding publishing frequency is {}",
                        detector.detector_id, detector.finding_publishing_frequency
                    ),
                )
            };

            reports.push(make_report(
                "guardduty_finding_publishing_frequency_six_hours_or_less",
                "Ensure GuardDuty finding publishing frequency is not set to SIX_HOURS",
                Severity::Low,
                status,
                &detector.detector_id,
                "",
                &detector.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
