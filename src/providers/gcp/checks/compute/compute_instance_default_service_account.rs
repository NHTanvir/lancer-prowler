use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::compute::make_report;
use crate::providers::gcp::services::compute::GcpComputeService;

pub struct ComputeInstanceDefaultServiceAccount;

const DEFAULT_COMPUTE_SA: &str = "compute@developer.gserviceaccount.com";

impl Check for ComputeInstanceDefaultServiceAccount {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_instance_default_service_account".to_string(),
            name: "Ensure that Compute Engine instances are not configured with the default service account".to_string(),
            description: "The default Compute Engine service account has an Editor role by default. \
                Using the default service account grants excessive permissions to all instances \
                in the project. Use a custom service account with minimal required permissions."
                .to_string(),
            severity: Severity::High,
            service: "compute".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "4.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-6".to_string(),
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

            let uses_default_sa = instance
                .service_account_email
                .as_deref()
                .map(|e| e.contains(DEFAULT_COMPUTE_SA))
                .unwrap_or(false);

            let (status, msg) = if uses_default_sa {
                (
                    Status::Fail,
                    format!(
                        "Instance {} uses the default Compute Engine service account",
                        instance.name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Instance {} does not use the default Compute Engine service account",
                        instance.name
                    ),
                )
            };

            reports.push(make_report(
                "compute_instance_default_service_account",
                "Ensure that Compute Engine instances are not configured with the default service account",
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
