use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::iam::make_report;
use crate::providers::gcp::services::iam::GcpIamService;

pub struct IamNoPublicAccess;

impl Check for IamNoPublicAccess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_no_public_access".to_string(),
            name: "Ensure that IAM bindings do not grant access to allUsers or allAuthenticatedUsers".to_string(),
            description: "Granting IAM roles to 'allUsers' or 'allAuthenticatedUsers' makes \
                project resources publicly accessible. This should be avoided to prevent \
                unintended exposure of sensitive data."
                .to_string(),
            severity: Severity::Critical,
            service: "iam".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "1.9".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-3".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<GcpIamService>() {
            Some(s) => s,
            None => return vec![],
        };

        let public_members = ["allUsers", "allAuthenticatedUsers"];
        let mut reports = Vec::new();

        for binding in &svc.project_bindings {
            for member in &binding.members {
                if public_members.contains(&member.as_str()) {
                    let resource_arn = format!(
                        "//cloudresourcemanager.googleapis.com/projects/{}/bindings/{}",
                        svc.project_id, binding.role
                    );
                    reports.push(make_report(
                        "iam_no_public_access",
                        "Ensure that IAM bindings do not grant access to allUsers or allAuthenticatedUsers",
                        Severity::Critical,
                        Status::Fail,
                        member,
                        &resource_arn,
                        "global",
                        &svc.project_id,
                        &format!(
                            "Role {} is granted to {} which allows public access",
                            binding.role, member
                        ),
                        self.metadata().compliance.clone(),
                    ));
                }
            }
        }

        if reports.is_empty() {
            reports.push(make_report(
                "iam_no_public_access",
                "Ensure that IAM bindings do not grant access to allUsers or allAuthenticatedUsers",
                Severity::Critical,
                Status::Pass,
                &svc.project_id,
                &format!("//cloudresourcemanager.googleapis.com/projects/{}", svc.project_id),
                "global",
                &svc.project_id,
                "No IAM bindings grant access to allUsers or allAuthenticatedUsers",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
