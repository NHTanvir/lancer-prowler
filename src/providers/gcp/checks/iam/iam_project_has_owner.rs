use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::iam::make_report;
use crate::providers::gcp::services::iam::GcpIamService;

pub struct IamProjectHasOwner;

impl Check for IamProjectHasOwner {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_project_has_owner".to_string(),
            name: "Ensure that the project has at least one owner".to_string(),
            description: "Every GCP project should have at least one designated owner to \
                ensure there is always a principal who can manage IAM policies and access."
                .to_string(),
            severity: Severity::Low,
            service: "iam".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "1.3".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<GcpIamService>() {
            Some(s) => s,
            None => return vec![],
        };

        let resource_arn = format!(
            "//cloudresourcemanager.googleapis.com/projects/{}",
            svc.project_id
        );

        let has_owner = svc
            .project_bindings
            .iter()
            .any(|b| b.role == "roles/owner");

        let (status, msg) = if has_owner {
            (
                Status::Pass,
                format!("Project {} has at least one owner binding", svc.project_id),
            )
        } else {
            (
                Status::Fail,
                format!("Project {} has no owner binding", svc.project_id),
            )
        };

        vec![make_report(
            "iam_project_has_owner",
            "Ensure that the project has at least one owner",
            Severity::Low,
            status,
            &svc.project_id,
            &resource_arn,
            "global",
            &svc.project_id,
            &msg,
            self.metadata().compliance.clone(),
        )]
    }
}
