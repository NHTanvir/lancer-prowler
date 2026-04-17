use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamPasswordPolicyReuse24;

impl Check for IamPasswordPolicyReuse24 {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_password_policy_reuse_24".to_string(),
            name: "Ensure IAM password policy prevents password reuse for 24 or more passwords"
                .to_string(),
            description: "IAM password policies can prevent the reuse of a given password. \
                Passwords should not be reused for at least 24 previous passwords."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.9".to_string(),
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
                let reuse = pp.password_reuse_prevention.unwrap_or(0);
                if reuse >= 24 {
                    (
                        Status::Pass,
                        format!(
                            "Password policy prevents reuse of {} previous passwords (>= 24)",
                            reuse
                        ),
                    )
                } else {
                    (
                        Status::Fail,
                        format!(
                            "Password policy prevents reuse of only {} previous passwords (must be >= 24)",
                            reuse
                        ),
                    )
                }
            }
        };

        vec![make_report(
            "iam_password_policy_reuse_24",
            "Ensure IAM password policy prevents password reuse for 24 or more passwords",
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
