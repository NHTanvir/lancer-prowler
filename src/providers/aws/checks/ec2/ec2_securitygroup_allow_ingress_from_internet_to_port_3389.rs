use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2SecuritygroupAllowIngressFromInternetToPort3389;

impl Check for Ec2SecuritygroupAllowIngressFromInternetToPort3389 {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_securitygroup_allow_ingress_from_internet_to_port_3389".to_string(),
            name: "Ensure no security group allows unrestricted RDP access from the internet"
                .to_string(),
            description:
                "Security groups should not allow unrestricted inbound RDP access (port 3389) \
                 from 0.0.0.0/0 or ::/0."
                    .to_string(),
            severity: Severity::Critical,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "5.3".to_string(),
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
                let open = sg.ingress_rules.iter().any(|r| {
                    let proto_ok = r.ip_protocol == "-1" || r.ip_protocol == "tcp";
                    let port_ok = r.ip_protocol == "-1"
                        || (r.from_port.unwrap_or(0) <= 3389
                            && r.to_port.unwrap_or(65535) >= 3389);
                    let internet =
                        r.ip_ranges.iter().any(|ip| ip == "0.0.0.0/0")
                            || r.ipv6_ranges.iter().any(|ip| ip == "::/0");
                    proto_ok && port_ok && internet
                });

                let (status, msg) = if open {
                    (
                        Status::Fail,
                        format!(
                            "Security group {} ({}) allows RDP (port 3389) from the internet",
                            sg.group_id, sg.group_name
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Security group {} ({}) does not allow RDP (port 3389) from the internet",
                            sg.group_id, sg.group_name
                        ),
                    )
                };

                make_report(
                    "ec2_securitygroup_allow_ingress_from_internet_to_port_3389",
                    "Ensure no security group allows unrestricted RDP access from the internet",
                    Severity::Critical,
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
