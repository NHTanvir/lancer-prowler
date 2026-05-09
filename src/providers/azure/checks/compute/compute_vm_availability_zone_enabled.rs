use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::compute::make_report;
use crate::providers::azure::services::compute::ComputeService;

pub struct ComputeVmAvailabilityZoneEnabled;

impl Check for ComputeVmAvailabilityZoneEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_vm_availability_zone_enabled".to_string(),
            name: "Ensure Azure Virtual Machines are deployed in availability zones".to_string(),
            description: "Deploying VMs in availability zones ensures resilience against \
                datacenter-level failures by distributing workloads across physically separate zones."
                .to_string(),
            severity: Severity::Low,
            service: "compute".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "CP-6".to_string(),
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

            let (status, msg) = match &vm.availability_zone {
                Some(zone) => (
                    Status::Pass,
                    format!(
                        "Virtual machine {} is deployed in availability zone {}",
                        vm.name, zone
                    ),
                ),
                None => (
                    Status::Fail,
                    format!(
                        "Virtual machine {} is not deployed in an availability zone",
                        vm.name
                    ),
                ),
            };

            reports.push(make_report(
                "compute_vm_availability_zone_enabled",
                "Ensure Azure Virtual Machines are deployed in availability zones",
                Severity::Low,
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
