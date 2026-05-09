use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::iam::make_report;
use crate::providers::gcp::services::iam::GcpIamService;

pub struct IamServiceAccountKeyNotUserManaged;

impl Check for IamServiceAccountKeyNotUserManaged {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_service_account_key_not_user_managed".to_string(),
            name: "Ensure that service account keys are not user-managed".to_string(),
            description: "User-managed service account keys are harder to rotate and audit. \
                Use system-managed keys or Workload Identity Federation instead."
                .to_string(),
            severity: Severity::Medium,
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

        let mut reports = Vec::new();

        for sa in &svc.service_accounts {
            let resource_arn = format!(
                "//iam.googleapis.com/projects/{}/serviceAccounts/{}",
                svc.project_id, sa.email
            );

            let user_managed_keys: Vec<&str> = sa
                .keys
                .iter()
                .filter(|k| k.key_type == "USER_MANAGED")
                .map(|k| k.key_id.as_str())
                .collect();

            let (status, msg) = if user_managed_keys.is_empty() {
                (
                    Status::Pass,
                    format!("Service account {} has no user-managed keys", sa.email),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Service account {} has {} user-managed key(s)",
                        sa.email,
                        user_managed_keys.len()
                    ),
                )
            };

            reports.push(make_report(
                "iam_service_account_key_not_user_managed",
                "Ensure that service account keys are not user-managed",
                Severity::Medium,
                status,
                &sa.email,
                &resource_arn,
                "global",
                &svc.project_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        if reports.is_empty() {
            reports.push(make_report(
                "iam_service_account_key_not_user_managed",
                "Ensure that service account keys are not user-managed",
                Severity::Medium,
                Status::Pass,
                &svc.project_id,
                &format!("//iam.googleapis.com/projects/{}", svc.project_id),
                "global",
                &svc.project_id,
                "No service accounts found",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
