use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamPasswordPolicyUppercase;

impl Check for IamPasswordPolicyUppercase {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_password_policy_uppercase".to_string(),
            name: "Ensure IAM password policy requires at least one uppercase letter".to_string(),
            description: "Password policies are used to enforce password complexity. \
                Requiring uppercase letters increases password strength."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.8".to_string(),
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
            None => (Status::Fail, "No password policy found".to_string()),
            Some(pp) => {
                if pp.require_uppercase {
                    (
                        Status::Pass,
                        "Password policy requires uppercase letters".to_string(),
                    )
                } else {
                    (
                        Status::Fail,
                        "Password policy does not require uppercase letters".to_string(),
                    )
                }
            }
        };

        vec![make_report(
            "iam_password_policy_uppercase",
            "Ensure IAM password policy requires at least one uppercase letter",
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
