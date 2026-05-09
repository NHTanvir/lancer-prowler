use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamPasswordPolicyMinimumLength14;

impl Check for IamPasswordPolicyMinimumLength14 {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_password_policy_minimum_length_14".to_string(),
            name: "Ensure IAM password policy requires minimum length of 14 or greater".to_string(),
            description: "Password policies are used to enforce password complexity requirements. \
                IAM password policies can be used to ensure passwords are at least 14 characters long."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.8".to_string(),
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
        let resource_arn = format!("arn:aws:iam::{}:root", account_id);

        let (status, msg) = match &iam.password_policy {
            None => (
                Status::Fail,
                "No password policy found".to_string(),
            ),
            Some(pp) => {
                let min_len = pp.minimum_password_length.unwrap_or(0);
                if min_len >= 14 {
                    (
                        Status::Pass,
                        format!("Password policy minimum length is {} (>= 14)", min_len),
                    )
                } else {
                    (
                        Status::Fail,
                        format!(
                            "Password policy minimum length is {} (must be >= 14)",
                            min_len
                        ),
                    )
                }
            }
        };

        vec![make_report(
            "iam_password_policy_minimum_length_14",
            "Ensure IAM password policy requires minimum length of 14 or greater",
            Severity::Medium,
            status,
            "password_policy",
            &resource_arn,
            "us-east-1",
            account_id,
            &msg,
            self.metadata().compliance.clone(),
        )]
    }
}
