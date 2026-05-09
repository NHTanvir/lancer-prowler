use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2SecuritygroupAllowWideOpenPublicIpv4;

impl Check for Ec2SecuritygroupAllowWideOpenPublicIpv4 {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_securitygroup_allow_wide_open_public_ipv4".to_string(),
            name: "Ensure no security group allows wide open inbound access from 0.0.0.0/0"
                .to_string(),
            description:
                "Security groups should not allow inbound traffic from 0.0.0.0/0 across \
                 a large port range (more than 1000 ports)."
                    .to_string(),
            severity: Severity::High,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "5.2".to_string(),
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

        svc.security_groups
            .iter()
            .map(|sg| {
                let wide_open = sg.ingress_rules.iter().any(|r| {
                    let from_internet = r.ip_ranges.iter().any(|ip| ip == "0.0.0.0/0");
                    let wide_range = match (r.from_port, r.to_port) {
                        (Some(from), Some(to)) => to - from > 1000,
                        _ => false,
                    };
                    from_internet && wide_range
                });

                let (status, msg) = if wide_open {
                    (
                        Status::Fail,
                        format!(
                            "Security group {} ({}) allows a wide port range from 0.0.0.0/0",
                            sg.group_id, sg.group_name
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Security group {} ({}) does not allow a wide port range from 0.0.0.0/0",
                            sg.group_id, sg.group_name
                        ),
                    )
                };

                make_report(
                    "ec2_securitygroup_allow_wide_open_public_ipv4",
                    "Ensure no security group allows wide open inbound access from 0.0.0.0/0",
                    Severity::High,
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
