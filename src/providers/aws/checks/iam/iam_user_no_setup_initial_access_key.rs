use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamUserNoSetupInitialAccessKey;

impl Check for IamUserNoSetupInitialAccessKey {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_user_no_setup_initial_access_key".to_string(),
            name: "Ensure IAM users receive permissions only through groups".to_string(),
            description: "Newly created IAM users should not have access keys created before \
                the user has first logged in. Detects users who have active access keys \
                but have never used the console."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.11".to_string(),
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

            // FAIL: access_key_1 is active AND password has never been used (N/A)
            let has_unused_initial_key = entry.access_key_1_active
                && (entry.password_last_used == "N/A" || entry.password_last_used.is_empty());

            let (status, msg) = if has_unused_initial_key {
                (
                    Status::Fail,
                    format!(
                        "User {} has an active access key but has never used the console — \
                        initial access key may not have been cleaned up",
                        entry.user
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "User {} does not have an unused initial access key",
                        entry.user
                    ),
                )
            };

            reports.push(make_report(
                "iam_user_no_setup_initial_access_key",
                "Ensure IAM users receive permissions only through groups",
                Severity::Medium,
                status,
                &entry.user,
                &user_arn,
                "us-east-1",
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
