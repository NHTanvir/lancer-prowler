use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2InstanceInternetFacingWithInstanceProfile;

impl Check for Ec2InstanceInternetFacingWithInstanceProfile {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_instance_internet_facing_with_instance_profile".to_string(),
            name:
                "Ensure internet-facing EC2 instances with instance profiles use least privilege"
                    .to_string(),
            description:
                "Internet-facing EC2 instances with an IAM instance profile attached present \
                 a higher risk: if compromised, the attacker can use the instance's IAM role \
                 to access AWS resources. Review these instances carefully."
                    .to_string(),
            severity: Severity::High,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-6".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-7".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<Ec2Service>() {
            Some(s) => s,
            None => return vec![],
        };

        svc.instances
            .iter()
            .map(|inst| {
                let risky = inst.public_ip.is_some() && inst.instance_profile_arn.is_some();

                let (status, msg) = if risky {
                    (
                        Status::Fail,
                        format!(
                            "Instance {} is internet-facing (IP: {}) and has an IAM instance \
                             profile attached ({}). Review for least privilege.",
                            inst.instance_id,
                            inst.public_ip.as_deref().unwrap_or("unknown"),
                            inst.instance_profile_arn.as_deref().unwrap_or("unknown")
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Instance {} is either not internet-facing or has no instance profile",
                            inst.instance_id
                        ),
                    )
                };

                make_report(
                    "ec2_instance_internet_facing_with_instance_profile",
                    "Ensure internet-facing EC2 instances with instance profiles use least privilege",
                    Severity::High,
                    status,
                    &inst.instance_id,
                    &inst.arn,
                    &inst.region,
                    &svc.account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                )
            })
            .collect()
    }
}
