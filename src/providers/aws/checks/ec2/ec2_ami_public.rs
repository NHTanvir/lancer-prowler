use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2AmiPublic;

impl Check for Ec2AmiPublic {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_ami_public".to_string(),
            name: "Ensure account-owned AMIs are not publicly accessible".to_string(),
            description:
                "AMIs owned by this account should not be public. Public AMIs can expose \
                 software configurations, credentials baked into images, or data volumes."
                    .to_string(),
            severity: Severity::Critical,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.2.3".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-3".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<Ec2Service>() {
            Some(s) => s,
            None => return vec![],
        };

        svc.amis
            .iter()
            .filter(|ami| ami.owner_id == svc.account_id)
            .map(|ami| {
                let (status, msg) = if ami.public {
                    (
                        Status::Fail,
                        format!(
                            "AMI {} ({}) is publicly accessible",
                            ami.image_id, ami.name
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!("AMI {} ({}) is not public", ami.image_id, ami.name),
                    )
                };

                make_report(
                    "ec2_ami_public",
                    "Ensure account-owned AMIs are not publicly accessible",
                    Severity::Critical,
                    status,
                    &ami.image_id,
                    &format!(
                        "arn:aws:ec2:{}::image/{}",
                        ami.region, ami.image_id
                    ),
                    &ami.region,
                    &svc.account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                )
            })
            .collect()
    }
}
