use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::vpc::make_report;
use crate::providers::aws::services::vpc::VpcService;

pub struct VpcSubnetNoPublicIpByDefault;

impl Check for VpcSubnetNoPublicIpByDefault {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "vpc_subnet_no_public_ip_by_default".to_string(),
            name: "Ensure VPC subnets do not automatically assign public IPs".to_string(),
            description: "Subnets with MapPublicIpOnLaunch enabled automatically expose \
                instances to the internet. Disable auto-assignment and use Elastic IPs \
                intentionally."
                .to_string(),
            severity: Severity::Medium,
            service: "vpc".to_string(),
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
        let svc = match context.downcast_ref::<VpcService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for subnet in &svc.subnets {
            let (status, msg) = if subnet.map_public_ip_on_launch {
                (
                    Status::Fail,
                    format!(
                        "Subnet {} in VPC {} automatically assigns public IPs on launch",
                        subnet.subnet_id, subnet.vpc_id
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Subnet {} in VPC {} does not automatically assign public IPs",
                        subnet.subnet_id, subnet.vpc_id
                    ),
                )
            };

            reports.push(make_report(
                "vpc_subnet_no_public_ip_by_default",
                "Ensure VPC subnets do not automatically assign public IPs",
                Severity::Medium,
                status,
                &subnet.subnet_id,
                &format!(
                    "arn:aws:ec2:{}:{}:subnet/{}",
                    subnet.region, account_id, subnet.subnet_id
                ),
                &subnet.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
