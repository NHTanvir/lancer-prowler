use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::compute::make_report;
use crate::providers::gcp::services::compute::GcpComputeService;

pub struct ComputeInstanceDefaultServiceAccountFullAccess;

const DEFAULT_COMPUTE_SA: &str = "compute@developer.gserviceaccount.com";
const FULL_ACCESS_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

impl Check for ComputeInstanceDefaultServiceAccountFullAccess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_instance_default_service_account_full_access".to_string(),
            name: "Ensure that Compute Engine instances are not configured with the default service account with full API access".to_string(),
            description: "Using the default Compute Engine service account with the \
                'cloud-platform' (full access) scope grants the instance access to all \
                GCP services, violating the principle of least privilege."
                .to_string(),
            severity: Severity::Critical,
            service: "compute".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "4.2".to_string(),
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

            let has_full_access = instance
                .service_account_scopes
                .iter()
                .any(|s| s == FULL_ACCESS_SCOPE);

            let (status, msg) = if uses_default_sa && has_full_access {
                (
                    Status::Fail,
                    format!(
                        "Instance {} uses the default Compute Engine service account with full API access scope",
                        instance.name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Instance {} is not using default service account with full API access",
                        instance.name
                    ),
                )
            };

            reports.push(make_report(
                "compute_instance_default_service_account_full_access",
                "Ensure that Compute Engine instances are not configured with the default service account with full API access",
                Severity::Critical,
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
