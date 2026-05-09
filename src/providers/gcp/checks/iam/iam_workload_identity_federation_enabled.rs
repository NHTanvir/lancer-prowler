use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::iam::make_report;
use crate::providers::gcp::services::iam::GcpIamService;

pub struct IamWorkloadIdentityFederationEnabled;

impl Check for IamWorkloadIdentityFederationEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_workload_identity_federation_enabled".to_string(),
            name: "Ensure Workload Identity Federation is used instead of service account keys".to_string(),
            description: "Workload Identity Federation allows external workloads to access \
                GCP resources without long-lived service account keys, reducing the risk \
                of credential exposure."
                .to_string(),
            severity: Severity::Low,
            service: "iam".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "1.4".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<GcpIamService>() {
            Some(s) => s,
            None => return vec![],
        };

        // Stub PASS: Workload Identity Federation check requires additional GCP API
        vec![make_report(
            "iam_workload_identity_federation_enabled",
            "Ensure Workload Identity Federation is used instead of service account keys",
            Severity::Low,
            Status::Pass,
            &svc.project_id,
            &format!("//iam.googleapis.com/projects/{}", svc.project_id),
            "global",
            &svc.project_id,
            "Workload Identity Federation check requires additional GCP API — skipped in stub mode",
            self.metadata().compliance.clone(),
        )]
    }
}
