use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess;

impl Check for IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_password_policy_expires_passwords_within_90_days_or_less".to_string(),
            name: "Ensure IAM password policy expires passwords within 90 days or less".to_string(),
            description: "IAM password policies can require passwords to be rotated or expired \
                after a given number of days. Passwords should expire within 90 days."
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
        let resource_arn = format!("arn:aws:iam::{}:root", account_id);

        let (status, msg) = match &iam.password_policy {
            None => (Status::Fail, "No password policy found".to_string()),
            Some(pp) => {
                let max_age = pp.max_password_age.unwrap_or(0);
                if pp.expire_passwords && max_age > 0 && max_age <= 90 {
                    (
                        Status::Pass,
                        format!(
                            "Password policy expires passwords every {} day(s) (<= 90)",
                            max_age
                        ),
                    )
                } else if !pp.expire_passwords {
                    (
                        Status::Fail,
                        "Password policy does not expire passwords".to_string(),
                    )
                } else if max_age == 0 {
                    (
                        Status::Fail,
                        "Password policy has max_password_age of 0 (no expiry set)".to_string(),
                    )
                } else {
                    (
                        Status::Fail,
                        format!(
                            "Password policy expires passwords every {} day(s) (must be <= 90)",
                            max_age
                        ),
                    )
                }
            }
        };

        vec![make_report(
            "iam_password_policy_expires_passwords_within_90_days_or_less",
            "Ensure IAM password policy expires passwords within 90 days or less",
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
