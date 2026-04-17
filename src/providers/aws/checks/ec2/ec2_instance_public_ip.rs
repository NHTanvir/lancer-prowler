use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2InstancePublicIp;

impl Check for Ec2InstancePublicIp {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_instance_public_ip".to_string(),
            name: "Ensure EC2 instances do not have a public IP address".to_string(),
            description:
                "EC2 instances with public IP addresses are directly reachable from the \
                 internet. Instances should be placed in private subnets where possible."
                    .to_string(),
            severity: Severity::Medium,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "5.1".to_string(),
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
                let (status, msg) = if inst.public_ip.is_some() {
                    (
                        Status::Fail,
                        format!(
                            "Instance {} has a public IP address: {}",
                            inst.instance_id,
                            inst.public_ip.as_deref().unwrap_or("unknown")
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Instance {} does not have a public IP address",
                            inst.instance_id
                        ),
                    )
                };

                make_report(
                    "ec2_instance_public_ip",
                    "Ensure EC2 instances do not have a public IP address",
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
