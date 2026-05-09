use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2SecuritygroupDefaultRestrictTraffic;

impl Check for Ec2SecuritygroupDefaultRestrictTraffic {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_securitygroup_default_restrict_traffic".to_string(),
            name: "Ensure the default security group restricts all traffic".to_string(),
            description:
                "The default security group should have no ingress rules and only the \
                 default allow-all outbound rule to prevent accidental exposure."
                    .to_string(),
            severity: Severity::High,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "5.4".to_string(),
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
            .filter(|sg| sg.group_name == "default")
            .map(|sg| {
                // FAIL if default SG has any ingress rules at all,
                // or if it has non-default egress (anything other than allow-all-outbound
                // which is protocol=-1 to 0.0.0.0/0 or ::/0).
                let has_ingress = !sg.ingress_rules.is_empty();

                // Non-default egress: any rule that is NOT the single allow-all rule
                let has_restrictive_egress = sg.egress_rules.iter().any(|r| {
                    !(r.ip_protocol == "-1"
                        && (r.ip_ranges.iter().any(|ip| ip == "0.0.0.0/0")
                            || r.ipv6_ranges.iter().any(|ip| ip == "::/0")))
                });

                let fail = has_ingress || has_restrictive_egress;

                let (status, msg) = if fail {
                    (
                        Status::Fail,
                        format!(
                            "Default security group {} in {} has unrestricted rules \
                             (ingress_rules={}, non_default_egress={})",
                            sg.group_id, sg.region, sg.ingress_rules.len(), has_restrictive_egress
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Default security group {} in {} has no ingress rules and \
                             only default egress",
                            sg.group_id, sg.region
                        ),
                    )
                };

                make_report(
                    "ec2_securitygroup_default_restrict_traffic",
                    "Ensure the default security group restricts all traffic",
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
