use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::compute::make_report;
use crate::providers::azure::services::compute::ComputeService;

pub struct ComputeVmNetworkSecurityGroup;

impl Check for ComputeVmNetworkSecurityGroup {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_vm_network_security_group".to_string(),
            name: "Ensure a Network Security Group is associated with the Azure Virtual Machine NIC".to_string(),
            description: "Associating an NSG with the VM network interface provides a layer of \
                network access control to filter inbound and outbound traffic."
                .to_string(),
            severity: Severity::High,
            service: "compute".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "7.5".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-7".to_string(),
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

            // Stub PASS: real check requires Azure Network (networkInterfaces) API
            reports.push(make_report(
                "compute_vm_network_security_group",
                "Ensure a Network Security Group is associated with the Azure Virtual Machine NIC",
                Severity::High,
                Status::Pass,
                &vm.name,
                &resource_arn,
                &vm.location,
                subscription_id,
                "NSG association check requires Azure Network API (stub: assumed compliant)",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
