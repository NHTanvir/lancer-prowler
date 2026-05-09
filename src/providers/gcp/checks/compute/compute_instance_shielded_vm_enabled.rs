use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::compute::make_report;
use crate::providers::gcp::services::compute::GcpComputeService;

pub struct ComputeInstanceShieldedVmEnabled;

impl Check for ComputeInstanceShieldedVmEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_instance_shielded_vm_enabled".to_string(),
            name: "Ensure that Shielded VM is enabled for Compute Engine instances".to_string(),
            description: "Shielded VMs use secure boot, vTPM, and integrity monitoring to \
                protect instances from rootkits and bootkits. Enabling Shielded VM helps \
                ensure the integrity of the compute instance's firmware and OS."
                .to_string(),
            severity: Severity::Medium,
            service: "compute".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "4.8".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<GcpComputeService>() {
            Some(s) => s,
            None => return vec![],
        };

        let mut reports = Vec::new();

        for instance in &svc.instances {
            let resource_arn = format!(
                "//compute.googleapis.com/projects/{}/zones/{}/instances/{}",
                svc.project_id, instance.zone, instance.name
            );

            let (status, msg) = if instance.shielded_vm_enabled {
                (
                    Status::Pass,
                    format!("Instance {} has Shielded VM enabled", instance.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Instance {} does not have Shielded VM enabled", instance.name),
                )
            };

            reports.push(make_report(
                "compute_instance_shielded_vm_enabled",
                "Ensure that Shielded VM is enabled for Compute Engine instances",
                Severity::Medium,
                status,
                &instance.name,
                &resource_arn,
                &instance.zone,
                &svc.project_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
