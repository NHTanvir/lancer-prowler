use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::compute::make_report;
use crate::providers::gcp::services::compute::GcpComputeService;

pub struct ComputeInstanceNoPublicIp;

impl Check for ComputeInstanceNoPublicIp {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_instance_no_public_ip".to_string(),
            name: "Ensure that Compute Engine instances do not have external IP addresses".to_string(),
            description: "Instances with external IP addresses are directly reachable from \
                the internet, increasing the attack surface. Use Cloud NAT or a bastion \
                host for outbound internet access instead."
                .to_string(),
            severity: Severity::Medium,
            service: "compute".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "4.9".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-7".to_string(),
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

            let (status, msg) = match &instance.public_ip {
                Some(ip) => (
                    Status::Fail,
                    format!("Instance {} has a public IP address: {}", instance.name, ip),
                ),
                None => (
                    Status::Pass,
                    format!("Instance {} has no public IP address", instance.name),
                ),
            };

            reports.push(make_report(
                "compute_instance_no_public_ip",
                "Ensure that Compute Engine instances do not have external IP addresses",
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
