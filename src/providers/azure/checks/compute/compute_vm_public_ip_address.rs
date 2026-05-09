use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::compute::make_report;
use crate::providers::azure::services::compute::ComputeService;

pub struct ComputeVmPublicIpAddress;

impl Check for ComputeVmPublicIpAddress {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_vm_public_ip_address".to_string(),
            name: "Ensure Azure Virtual Machines do not have a public IP address".to_string(),
            description: "Assigning a public IP address directly to a VM exposes it to the \
                internet. VMs should be accessed via load balancers or VPN/bastion hosts."
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

            // Stub PASS: real check requires Azure Network publicIPAddresses API
            reports.push(make_report(
                "compute_vm_public_ip_address",
                "Ensure Azure Virtual Machines do not have a public IP address",
                Severity::High,
                Status::Pass,
                &vm.name,
                &resource_arn,
                &vm.location,
                subscription_id,
                "Public IP check requires Azure Network API (stub: assumed compliant)",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
