use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::compute::make_report;
use crate::providers::gcp::services::compute::GcpComputeService;

pub struct ComputeInstanceIpForwardingDisabled;

impl Check for ComputeInstanceIpForwardingDisabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_instance_ip_forwarding_disabled".to_string(),
            name: "Ensure that IP forwarding is disabled on Compute Engine instances".to_string(),
            description: "Enabling IP forwarding allows an instance to forward packets not \
                addressed to it. This should be disabled unless the instance is intentionally \
                acting as a router or gateway to prevent packet interception."
                .to_string(),
            severity: Severity::High,
            service: "compute".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "4.3".to_string(),
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

            let (status, msg) = if instance.can_ip_forward {
                (
                    Status::Fail,
                    format!("Instance {} has IP forwarding enabled", instance.name),
                )
            } else {
                (
                    Status::Pass,
                    format!("Instance {} has IP forwarding disabled", instance.name),
                )
            };

            reports.push(make_report(
                "compute_instance_ip_forwarding_disabled",
                "Ensure that IP forwarding is disabled on Compute Engine instances",
                Severity::High,
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
