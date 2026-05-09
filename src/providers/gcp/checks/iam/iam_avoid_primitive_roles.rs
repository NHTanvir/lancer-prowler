use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::iam::make_report;
use crate::providers::gcp::services::iam::GcpIamService;

pub struct IamAvoidPrimitiveRoles;

impl Check for IamAvoidPrimitiveRoles {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_avoid_primitive_roles".to_string(),
            name: "Ensure that primitive roles (Owner, Editor, Viewer) are not used".to_string(),
            description: "Primitive roles (roles/owner, roles/editor, roles/viewer) grant \
                coarse-grained access to all GCP services. Use predefined or custom roles \
                to follow least-privilege principles."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "1.4".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-6".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<GcpIamService>() {
            Some(s) => s,
            None => return vec![],
        };

        let primitive_roles = ["roles/owner", "roles/editor", "roles/viewer"];
        let mut reports = Vec::new();

        for binding in &svc.project_bindings {
            if primitive_roles.contains(&binding.role.as_str()) {
                let resource_arn = format!(
                    "//cloudresourcemanager.googleapis.com/projects/{}/bindings/{}",
                    svc.project_id, binding.role
                );
                reports.push(make_report(
                    "iam_avoid_primitive_roles",
                    "Ensure that primitive roles (Owner, Editor, Viewer) are not used",
                    Severity::Medium,
                    Status::Fail,
                    &binding.role,
                    &resource_arn,
                    "global",
                    &svc.project_id,
                    &format!(
                        "Primitive role {} is assigned to {} member(s)",
                        binding.role,
                        binding.members.len()
                    ),
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_report(
                "iam_avoid_primitive_roles",
                "Ensure that primitive roles (Owner, Editor, Viewer) are not used",
                Severity::Medium,
                Status::Pass,
                &svc.project_id,
                &format!("//cloudresourcemanager.googleapis.com/projects/{}", svc.project_id),
                "global",
                &svc.project_id,
                "No primitive roles are assigned in this project",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
