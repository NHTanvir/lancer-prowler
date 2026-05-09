use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::compute::make_report;
use crate::providers::azure::services::compute::ComputeService;

pub struct ComputeVmDataDisksEncrypted;

impl Check for ComputeVmDataDisksEncrypted {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_vm_data_disks_encrypted".to_string(),
            name: "Ensure that data disks are encrypted for Azure Virtual Machines".to_string(),
            description: "Encrypting data disks protects sensitive data stored on attached disks \
                from unauthorized access if the physical media is compromised."
                .to_string(),
            severity: Severity::High,
            service: "compute".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "7.3".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-28".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<ComputeService>() {
            Some(s) => s,
            None => return vec![],
        };

        let subscription_id = &svc.subscription_id;
        let mut reports = Vec::new();

        for vm in &svc.virtual_machines {
            let resource_arn = format!(
                "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}",
                subscription_id, vm.resource_group, vm.name
            );

            let (status, msg) = if vm.data_disks_encrypted {
                (
                    Status::Pass,
                    format!("Virtual machine {} has all data disks encrypted", vm.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Virtual machine {} has unencrypted data disks", vm.name),
                )
            };

            reports.push(make_report(
                "compute_vm_data_disks_encrypted",
                "Ensure that data disks are encrypted for Azure Virtual Machines",
                Severity::High,
                status,
                &vm.name,
                &resource_arn,
                &vm.location,
                subscription_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
