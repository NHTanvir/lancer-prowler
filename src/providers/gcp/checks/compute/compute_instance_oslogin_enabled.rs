use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::compute::make_report;
use crate::providers::gcp::services::compute::GcpComputeService;

pub struct ComputeInstanceOsloginEnabled;

impl Check for ComputeInstanceOsloginEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_instance_oslogin_enabled".to_string(),
            name: "Ensure that OS Login is enabled for Compute Engine instances".to_string(),
            description: "OS Login ties SSH access to IAM identity, enabling centralized \
                management of SSH keys and two-factor authentication. It removes the need \
                to manage SSH keys in instance metadata."
                .to_string(),
            severity: Severity::Medium,
            service: "compute".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "4.4".to_string(),
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

            let (status, msg) = if instance.oslogin_enabled {
                (
                    Status::Pass,
                    format!("Instance {} has OS Login enabled", instance.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Instance {} does not have OS Login enabled", instance.name),
                )
            };

            reports.push(make_report(
                "compute_instance_oslogin_enabled",
                "Ensure that OS Login is enabled for Compute Engine instances",
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
