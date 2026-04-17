use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2SecuritygroupNotUsed;

impl Check for Ec2SecuritygroupNotUsed {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_securitygroup_not_used".to_string(),
            name: "Ensure unused security groups are removed".to_string(),
            description:
                "Security groups that are not attached to any resource should be removed \
                 to reduce the attack surface and improve hygiene."
                    .to_string(),
            severity: Severity::Low,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![ComplianceRef {
                framework: "NIST_800_53_Rev5".to_string(),
                control_id: "CM-7".to_string(),
            }],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<Ec2Service>() {
            Some(s) => s,
            None => return vec![],
        };

        svc.security_groups
            .iter()
            .filter(|sg| sg.group_name != "default")
            .map(|sg| {
                let (status, msg) = if !sg.in_use {
                    (
                        Status::Fail,
                        format!(
                            "Security group {} ({}) is not attached to any resource",
                            sg.group_id, sg.group_name
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Security group {} ({}) is in use",
                            sg.group_id, sg.group_name
                        ),
                    )
                };

                make_report(
                    "ec2_securitygroup_not_used",
                    "Ensure unused security groups are removed",
                    Severity::Low,
                    status,
                    &sg.group_id,
                    &format!(
                        "arn:aws:ec2:{}:{}:security-group/{}",
                        sg.region, svc.account_id, sg.group_id
                    ),
                    &sg.region,
                    &svc.account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                )
            })
            .collect()
    }
}
