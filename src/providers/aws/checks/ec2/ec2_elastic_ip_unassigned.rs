use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2ElasticIpUnassigned;

impl Check for Ec2ElasticIpUnassigned {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_elastic_ip_unassigned".to_string(),
            name: "Ensure unassigned Elastic IP addresses are released".to_string(),
            description:
                "Elastic IP addresses that are not associated with a running instance or \
                 network interface incur charges and represent unused resources that should \
                 be released."
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

        svc.elastic_ips
            .iter()
            .map(|eip| {
                let unassigned = eip.associated_instance_id.is_none()
                    && eip.associated_network_interface_id.is_none();

                let (status, msg) = if unassigned {
                    (
                        Status::Fail,
                        format!(
                            "Elastic IP {} ({}) is not associated with any instance or \
                             network interface",
                            eip.allocation_id, eip.public_ip
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Elastic IP {} ({}) is associated with a resource",
                            eip.allocation_id, eip.public_ip
                        ),
                    )
                };

                make_report(
                    "ec2_elastic_ip_unassigned",
                    "Ensure unassigned Elastic IP addresses are released",
                    Severity::Low,
                    status,
                    &eip.allocation_id,
                    &format!(
                        "arn:aws:ec2:{}:{}:elastic-ip/{}",
                        eip.region, svc.account_id, eip.allocation_id
                    ),
                    &eip.region,
                    &svc.account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                )
            })
            .collect()
    }
}
