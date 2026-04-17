use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2EbsVolumeEncryption;

impl Check for Ec2EbsVolumeEncryption {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_ebs_volume_encryption".to_string(),
            name: "Ensure all EBS volumes are encrypted at rest".to_string(),
            description:
                "EBS volumes should be encrypted to protect sensitive data stored on them."
                    .to_string(),
            severity: Severity::Medium,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.2.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-28".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<Ec2Service>() {
            Some(s) => s,
            None => return vec![],
        };

        svc.ebs_volumes
            .iter()
            .map(|vol| {
                let (status, msg) = if vol.encrypted {
                    (
                        Status::Pass,
                        format!("EBS volume {} is encrypted", vol.volume_id),
                    )
                } else {
                    (
                        Status::Fail,
                        format!("EBS volume {} is NOT encrypted", vol.volume_id),
                    )
                };

                make_report(
                    "ec2_ebs_volume_encryption",
                    "Ensure all EBS volumes are encrypted at rest",
                    Severity::Medium,
                    status,
                    &vol.volume_id,
                    &vol.arn,
                    &vol.region,
                    &svc.account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                )
            })
            .collect()
    }
}
