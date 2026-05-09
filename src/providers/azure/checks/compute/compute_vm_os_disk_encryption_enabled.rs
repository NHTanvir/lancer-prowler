use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::compute::make_report;
use crate::providers::azure::services::compute::ComputeService;

pub struct ComputeVmOsDiskEncryptionEnabled;

impl Check for ComputeVmOsDiskEncryptionEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_vm_os_disk_encryption_enabled".to_string(),
            name: "Ensure that OS disk encryption is enabled for Azure Virtual Machines".to_string(),
            description: "Encrypting the OS disk of a virtual machine protects data at rest and \
                prevents unauthorized access if the physical media is removed."
                .to_string(),
            severity: Severity::High,
            service: "compute".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "7.2".to_string(),
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

            let (status, msg) = if vm.os_disk_encryption {
                (
                    Status::Pass,
                    format!("Virtual machine {} has OS disk encryption enabled", vm.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Virtual machine {} does not have OS disk encryption enabled", vm.name),
                )
            };

            reports.push(make_report(
                "compute_vm_os_disk_encryption_enabled",
                "Ensure that OS disk encryption is enabled for Azure Virtual Machines",
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
