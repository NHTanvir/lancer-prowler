use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2InstanceParavirtualType;

impl Check for Ec2InstanceParavirtualType {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_instance_paravirtual_type".to_string(),
            name: "Ensure EC2 instances do not use paravirtual (PV) virtualization".to_string(),
            description:
                "Paravirtual (PV) instances are an older virtualization type that is deprecated \
                 and lacks security features available in hardware virtual machine (HVM) instances."
                    .to_string(),
            severity: Severity::Medium,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![ComplianceRef {
                framework: "NIST_800_53_Rev5".to_string(),
                control_id: "SI-2".to_string(),
            }],
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
                let is_pv = inst.virtualization_type == "paravirtual";
                let (status, msg) = if is_pv {
                    (
                        Status::Fail,
                        format!(
                            "Instance {} uses paravirtual (PV) virtualization type",
                            inst.instance_id
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Instance {} uses HVM virtualization type",
                            inst.instance_id
                        ),
                    )
                };

                make_report(
                    "ec2_instance_paravirtual_type",
                    "Ensure EC2 instances do not use paravirtual (PV) virtualization",
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
