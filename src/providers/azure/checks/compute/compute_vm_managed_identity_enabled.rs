use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::compute::make_report;
use crate::providers::azure::services::compute::ComputeService;

pub struct ComputeVmManagedIdentityEnabled;

impl Check for ComputeVmManagedIdentityEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_vm_managed_identity_enabled".to_string(),
            name: "Ensure Azure Virtual Machines are using Managed Identities".to_string(),
            description: "Using managed identities for Azure VMs eliminates the need for \
                credentials in code and enables secure access to Azure services."
                .to_string(),
            severity: Severity::Medium,
            service: "compute".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "9.2".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "IA-2".to_string(),
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

            let (status, msg) = if vm.managed_identity_enabled {
                (
                    Status::Pass,
                    format!("Virtual machine {} has a managed identity enabled", vm.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Virtual machine {} does not have a managed identity enabled", vm.name),
                )
            };

            reports.push(make_report(
                "compute_vm_managed_identity_enabled",
                "Ensure Azure Virtual Machines are using Managed Identities",
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
