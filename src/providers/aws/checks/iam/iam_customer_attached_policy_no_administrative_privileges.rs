use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::{make_report, policy_has_admin_access};
use crate::providers::aws::services::iam::IamService;

pub struct IamCustomerAttachedPolicyNoAdministrativePrivileges;

impl Check for IamCustomerAttachedPolicyNoAdministrativePrivileges {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_customer_attached_policy_no_administrative_privileges".to_string(),
            name: "Ensure customer-managed policies do not grant administrative privileges"
                .to_string(),
            description: "Customer-managed IAM policies that grant full administrative access \
                (Action:*, Resource:*) represent a significant security risk."
                .to_string(),
            severity: Severity::Critical,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.16".to_string(),
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

        for policy in &iam.policies {
            if policy.is_aws_managed {
                continue;
            }

            let has_admin = policy_has_admin_access(&policy.document);
            let (status, msg) = if has_admin {
                (
                    Status::Fail,
                    format!(
                        "Customer-managed policy {} grants full administrative access \
                        (Effect:Allow Action:* Resource:*)",
                        policy.policy_name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Customer-managed policy {} does not grant full administrative access",
                        policy.policy_name
                    ),
                )
            };

            reports.push(make_report(
                "iam_customer_attached_policy_no_administrative_privileges",
                "Ensure customer-managed policies do not grant administrative privileges",
                Severity::Critical,
                status,
                &policy.policy_name,
                &policy.arn,
                "us-east-1",
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
