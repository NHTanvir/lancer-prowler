use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::{make_report, older_than_days};
use crate::providers::aws::services::iam::IamService;

pub struct IamRotateAccessKey90Days;

impl Check for IamRotateAccessKey90Days {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_rotate_access_key_90_days".to_string(),
            name: "Ensure access keys are rotated every 90 days or less".to_string(),
            description: "Access keys should be rotated regularly to reduce the risk of \
                long-lived credentials being compromised. Rotate every 90 days or less."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.14".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "IA-5".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let iam = match context.downcast_ref::<IamService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &iam.account_id;
        let mut reports = Vec::new();

        for entry in &iam.credential_report {
            if entry.user == "<root_account>" {
                continue;
            }

            let user_arn = iam
                .users
                .iter()
                .find(|u| u.user_name == entry.user)
                .map(|u| u.arn.clone())
                .unwrap_or_else(|| format!("arn:aws:iam::{}:user/{}", account_id, entry.user));

            // Check access key 1
            if entry.access_key_1_active {
                let key_id = iam
                    .users
                    .iter()
                    .find(|u| u.user_name == entry.user)
                    .and_then(|u| u.access_keys.iter().find(|k| k.status == "Active"))
                    .map(|k| k.access_key_id.clone())
                    .unwrap_or_else(|| "access_key_1".to_string());

                let resource_id = format!("{}/{}", entry.user, key_id);
                let rotated = &entry.access_key_1_last_rotated;
                let is_old = older_than_days(rotated, 90);
                let (status, msg) = if is_old {
                    (
                        Status::Fail,
                        format!(
                            "Access key for user {} was last rotated on {} (> 90 days ago)",
                            entry.user, rotated
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Access key for user {} was last rotated on {} (<= 90 days ago)",
                            entry.user, rotated
                        ),
                    )
                };
                reports.push(make_report(
                    "iam_rotate_access_key_90_days",
                    "Ensure access keys are rotated every 90 days or less",
                    Severity::Medium,
                    status,
                    &resource_id,
                    &user_arn,
                    "us-east-1",
                    account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                ));
            }

            // Check access key 2
            if entry.access_key_2_active {
                let resource_id = format!("{}/access_key_2", entry.user);
                let rotated = &entry.access_key_2_last_rotated;
                let is_old = older_than_days(rotated, 90);
                let (status, msg) = if is_old {
                    (
                        Status::Fail,
                        format!(
                            "Access key 2 for user {} was last rotated on {} (> 90 days ago)",
                            entry.user, rotated
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Access key 2 for user {} was last rotated on {} (<= 90 days ago)",
                            entry.user, rotated
                        ),
                    )
                };
                reports.push(make_report(
                    "iam_rotate_access_key_90_days",
                    "Ensure access keys are rotated every 90 days or less",
                    Severity::Medium,
                    status,
                    &resource_id,
                    &user_arn,
                    "us-east-1",
                    account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                ));
            }
        }

        reports
    }
}
