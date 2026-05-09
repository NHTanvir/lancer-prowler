use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::iam::make_report;
use crate::providers::gcp::services::iam::GcpIamService;

pub struct IamSaNoAdminPrivileges;

impl Check for IamSaNoAdminPrivileges {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_sa_no_admin_privileges".to_string(),
            name: "Ensure that service accounts are not granted security admin or role admin privileges".to_string(),
            description: "Service accounts should not have roles/iam.securityAdmin or \
                roles/iam.roleAdmin as these roles allow managing IAM policies, \
                which can be used for privilege escalation."
                .to_string(),
            severity: Severity::High,
            service: "iam".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "1.5".to_string(),
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

        let dangerous_roles = ["roles/iam.securityAdmin", "roles/iam.roleAdmin"];
        let mut reports = Vec::new();

        for binding in &svc.project_bindings {
            if !dangerous_roles.contains(&binding.role.as_str()) {
                continue;
            }
            for member in &binding.members {
                if member.starts_with("serviceAccount:") {
                    let resource_arn = format!(
                        "//cloudresourcemanager.googleapis.com/projects/{}/bindings/{}",
                        svc.project_id, binding.role
                    );
                    reports.push(make_report(
                        "iam_sa_no_admin_privileges",
                        "Ensure that service accounts are not granted security admin or role admin privileges",
                        Severity::High,
                        Status::Fail,
                        member,
                        &resource_arn,
                        "global",
                        &svc.project_id,
                        &format!(
                            "Service account {} has privileged role {}",
                            member, binding.role
                        ),
                        self.metadata().compliance.clone(),
                    ));
                }
            }
        }

        if reports.is_empty() {
            reports.push(make_report(
                "iam_sa_no_admin_privileges",
                "Ensure that service accounts are not granted security admin or role admin privileges",
                Severity::High,
                Status::Pass,
                &svc.project_id,
                &format!("//cloudresourcemanager.googleapis.com/projects/{}", svc.project_id),
                "global",
                &svc.project_id,
                "No service accounts have security admin or role admin privileges",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
