use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2InstanceManagedBySsm;

impl Check for Ec2InstanceManagedBySsm {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_instance_managed_by_ssm".to_string(),
            name: "Ensure EC2 instances are managed by AWS Systems Manager".to_string(),
            description:
                "EC2 instances should be managed by AWS Systems Manager (SSM) to enable \
                 patch management, inventory, and session manager access without opening SSH."
                    .to_string(),
            severity: Severity::Medium,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SI-2".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "CM-7".to_string(),
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
                let (status, msg) = if inst.managed_by_ssm {
                    (
                        Status::Pass,
                        format!(
                            "Instance {} is managed by AWS Systems Manager",
                            inst.instance_id
                        ),
                    )
                } else {
                    (
                        Status::Fail,
                        format!(
                            "Instance {} is NOT managed by AWS Systems Manager",
                            inst.instance_id
                        ),
                    )
                };

                make_report(
                    "ec2_instance_managed_by_ssm",
                    "Ensure EC2 instances are managed by AWS Systems Manager",
                    Severity::Medium,
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
