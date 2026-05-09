use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::iam::make_report;
use crate::providers::gcp::services::iam::GcpIamService;

pub struct IamServiceAccountKeyRotation90Days;

impl Check for IamServiceAccountKeyRotation90Days {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_service_account_key_rotation_90_days".to_string(),
            name: "Ensure that user-managed service account keys are rotated within 90 days".to_string(),
            description: "User-managed service account keys that are older than 90 days \
                present an elevated security risk due to potential exposure over time. \
                Keys should be rotated regularly to limit the blast radius of credential compromise."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "1.7".to_string(),
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
        let ninety_days = chrono::Duration::days(90);
        let now = chrono::Utc::now();

        for sa in &svc.service_accounts {
            for key in &sa.keys {
                if key.key_type != "USER_MANAGED" {
                    continue;
                }

                let resource_arn = format!(
                    "//iam.googleapis.com/projects/{}/serviceAccounts/{}/keys/{}",
                    svc.project_id, sa.email, key.key_id
                );

                // Parse valid_after date; if parsing fails, treat as PASS
                let (status, msg) = match chrono::DateTime::parse_from_rfc3339(&key.valid_after) {
                    Ok(created_at) => {
                        let age = now.signed_duration_since(created_at);
                        if age > ninety_days {
                            (
                                Status::Fail,
                                format!(
                                    "Service account {} key {} is {} days old (exceeds 90 days)",
                                    sa.email,
                                    key.key_id,
                                    age.num_days()
                                ),
                            )
                        } else {
                            (
                                Status::Pass,
                                format!(
                                    "Service account {} key {} is {} days old (within 90 days)",
                                    sa.email,
                                    key.key_id,
                                    age.num_days()
                                ),
                            )
                        }
                    }
                    Err(_) => (
                        Status::Pass,
                        format!(
                            "Service account {} key {} valid_after date could not be parsed",
                            sa.email, key.key_id
                        ),
                    ),
                };

                reports.push(make_report(
                    "iam_service_account_key_rotation_90_days",
                    "Ensure that user-managed service account keys are rotated within 90 days",
                    Severity::Medium,
                    status,
                    &key.key_id,
                    &resource_arn,
                    "global",
                    &svc.project_id,
                    &msg,
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_report(
                "iam_service_account_key_rotation_90_days",
                "Ensure that user-managed service account keys are rotated within 90 days",
                Severity::Medium,
                Status::Pass,
                &svc.project_id,
                &format!("//iam.googleapis.com/projects/{}", svc.project_id),
                "global",
                &svc.project_id,
                "No user-managed service account keys found",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
