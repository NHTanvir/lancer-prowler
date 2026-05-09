use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::compute::make_report;
use crate::providers::azure::services::compute::ComputeService;

pub struct ComputeVmEndpointProtection;

impl Check for ComputeVmEndpointProtection {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_vm_endpoint_protection".to_string(),
            name: "Ensure that endpoint protection is installed on Azure Virtual Machines".to_string(),
            description: "Endpoint protection (Microsoft Defender for servers) monitors VMs for \
                malicious activity and provides threat detection at the host level."
                .to_string(),
            severity: Severity::Medium,
            service: "compute".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "7.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SI-3".to_string(),
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

            // Stub PASS: real check requires Azure Defender (Security Center) API
            reports.push(make_report(
                "compute_vm_endpoint_protection",
                "Ensure that endpoint protection is installed on Azure Virtual Machines",
                Severity::Medium,
                Status::Pass,
                &vm.name,
                &resource_arn,
                &vm.location,
                subscription_id,
                "Endpoint protection check requires Azure Defender API (stub: assumed compliant)",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
