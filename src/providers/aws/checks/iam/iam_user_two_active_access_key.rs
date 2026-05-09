use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamUserTwoActiveAccessKey;

impl Check for IamUserTwoActiveAccessKey {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_user_two_active_access_key".to_string(),
            name: "Ensure there is only one active access key available for any single IAM user"
                .to_string(),
            description: "Access keys are long-term credentials for an IAM user. Having two \
                active access keys doubles the attack surface. Each user should have no more \
                than one active access key."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.13".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-2".to_string(),
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

        for user in &iam.users {
            let active_key_count = user
                .access_keys
                .iter()
                .filter(|k| k.status == "Active")
                .count();

            let (status, msg) = if active_key_count >= 2 {
                (
                    Status::Fail,
                    format!(
                        "User {} has {} active access keys (maximum allowed: 1)",
                        user.user_name, active_key_count
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "User {} has {} active access key(s)",
                        user.user_name, active_key_count
                    ),
                )
            };

            reports.push(make_report(
                "iam_user_two_active_access_key",
                "Ensure there is only one active access key available for any single IAM user",
                Severity::Medium,
                status,
                &user.user_name,
                &user.arn,
                "us-east-1",
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
