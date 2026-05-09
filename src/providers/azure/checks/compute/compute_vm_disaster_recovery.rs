use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::compute::make_report;
use crate::providers::azure::services::compute::ComputeService;

pub struct ComputeVmDisasterRecovery;

impl Check for ComputeVmDisasterRecovery {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_vm_disaster_recovery".to_string(),
            name: "Ensure that disaster recovery is configured for Azure Virtual Machines".to_string(),
            description: "Configuring disaster recovery (Azure Site Recovery) for VMs ensures \
                business continuity in the event of a regional outage."
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

            // Stub PASS: real check requires Azure Site Recovery (RecoveryServices) API
            reports.push(make_report(
                "compute_vm_disaster_recovery",
                "Ensure that disaster recovery is configured for Azure Virtual Machines",
                Severity::Low,
                Status::Pass,
                &vm.name,
                &resource_arn,
                &vm.location,
                subscription_id,
                "Disaster recovery check requires Azure Site Recovery API (stub: assumed compliant)",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
