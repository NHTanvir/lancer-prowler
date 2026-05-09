use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::guardduty::make_report;
use crate::providers::aws::services::guardduty::GuardDutyService;

pub struct GuardDutyIsEnabled;

impl Check for GuardDutyIsEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "guardduty_is_enabled".to_string(),
            name: "Ensure GuardDuty is enabled in all regions".to_string(),
            description: "Amazon GuardDuty is a threat detection service that continuously \
                monitors for malicious activity. It should be enabled in all regions."
                .to_string(),
            severity: Severity::High,
            service: "guardduty".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_1.4".to_string(),
                    control_id: "3.8".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SI-3".to_string(),
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

        // Check each scanned region for an active detector
        for region in &svc.scanned_regions {
            let detectors_in_region: Vec<_> = svc
                .detectors
                .iter()
                .filter(|d| &d.region == region)
                .collect();

            let enabled = detectors_in_region
                .iter()
                .any(|d| d.status == "ENABLED");

            if detectors_in_region.is_empty() || !enabled {
                reports.push(make_report(
                    "guardduty_is_enabled",
                    "Ensure GuardDuty is enabled in all regions",
                    Severity::High,
                    Status::Fail,
                    region,
                    "",
                    region,
                    account_id,
                    &format!("GuardDuty is not enabled in region {region}"),
                    self.metadata().compliance.clone(),
                ));
            } else {
                let detector_id = detectors_in_region[0].detector_id.as_str();
                reports.push(make_report(
                    "guardduty_is_enabled",
                    "Ensure GuardDuty is enabled in all regions",
                    Severity::High,
                    Status::Pass,
                    detector_id,
                    "",
                    region,
                    account_id,
                    &format!("GuardDuty is enabled in region {region}"),
                    self.metadata().compliance.clone(),
                ));
            }
        }

        reports
    }
}
