use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2InstanceSecretsUserData;

impl Check for Ec2InstanceSecretsUserData {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_instance_secrets_user_data".to_string(),
            name: "Ensure EC2 user data does not contain secrets or credentials".to_string(),
            description:
                "EC2 instance user data is accessible to anyone with DescribeInstances \
                 permission and should not contain plaintext secrets, passwords, or API keys."
                    .to_string(),
            severity: Severity::Critical,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "IA-5".to_string(),
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
                let (status, msg) = if inst.user_data_has_secrets {
                    (
                        Status::Fail,
                        format!(
                            "Instance {} user data appears to contain secrets or credentials",
                            inst.instance_id
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Instance {} user data does not appear to contain secrets",
                            inst.instance_id
                        ),
                    )
                };

                make_report(
                    "ec2_instance_secrets_user_data",
                    "Ensure EC2 user data does not contain secrets or credentials",
                    Severity::Critical,
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
