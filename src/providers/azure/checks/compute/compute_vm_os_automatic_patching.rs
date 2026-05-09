use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::compute::make_report;
use crate::providers::azure::services::compute::ComputeService;

pub struct ComputeVmOsAutomaticPatching;

impl Check for ComputeVmOsAutomaticPatching {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_vm_os_automatic_patching".to_string(),
            name: "Ensure Azure Virtual Machines use automatic OS patching".to_string(),
            description: "Configuring automatic OS patching ensures VMs receive security \
                patches promptly, reducing the window of exposure to known vulnerabilities."
                .to_string(),
            severity: Severity::Medium,
            service: "compute".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "7.6".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SI-2".to_string(),
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

            let (status, msg) = if vm.patch_mode != "Manual" {
                (
                    Status::Pass,
                    format!(
                        "Virtual machine {} has automatic OS patching enabled (patch mode: {})",
                        vm.name, vm.patch_mode
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Virtual machine {} has patch mode set to Manual; automatic patching recommended",
                        vm.name
                    ),
                )
            };

            reports.push(make_report(
                "compute_vm_os_automatic_patching",
                "Ensure Azure Virtual Machines use automatic OS patching",
                Severity::Medium,
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
