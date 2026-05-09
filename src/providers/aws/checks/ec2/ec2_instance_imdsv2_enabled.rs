use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2InstanceImdsv2Enabled;

impl Check for Ec2InstanceImdsv2Enabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_instance_imdsv2_enabled".to_string(),
            name: "Ensure IMDSv2 is required on all EC2 instances".to_string(),
            description:
                "EC2 instances should require IMDSv2 (HttpTokens=required) to prevent \
                 SSRF-based metadata credential theft attacks."
                    .to_string(),
            severity: Severity::High,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "5.6".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-17".to_string(),
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
                let (status, msg) = if inst.imdsv2_required {
                    (
                        Status::Pass,
                        format!(
                            "Instance {} requires IMDSv2 (HttpTokens=required)",
                            inst.instance_id
                        ),
                    )
                } else {
                    (
                        Status::Fail,
                        format!(
                            "Instance {} does not require IMDSv2 (HttpTokens is optional)",
                            inst.instance_id
                        ),
                    )
                };

                make_report(
                    "ec2_instance_imdsv2_enabled",
                    "Ensure IMDSv2 is required on all EC2 instances",
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
