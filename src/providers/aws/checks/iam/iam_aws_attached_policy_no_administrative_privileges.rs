use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

const ADMIN_POLICY_ARN: &str = "arn:aws:iam::aws:policy/AdministratorAccess";

pub struct IamAwsAttachedPolicyNoAdministrativePrivileges;

impl Check for IamAwsAttachedPolicyNoAdministrativePrivileges {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_aws_attached_policy_no_administrative_privileges".to_string(),
            name: "Ensure IAM users and roles do not have AdministratorAccess attached".to_string(),
            description: "The AWS-managed AdministratorAccess policy grants full access to all \
                AWS services and resources. It should not be attached directly to users or roles \
                in normal operations."
                .to_string(),
            severity: Severity::High,
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

        // Check users
        for user in &iam.users {
            let has_admin = user
                .attached_policies
                .iter()
                .any(|p| p == ADMIN_POLICY_ARN);

            let (status, msg) = if has_admin {
                (
                    Status::Fail,
                    format!(
                        "User {} has AdministratorAccess policy attached",
                        user.user_name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "User {} does not have AdministratorAccess policy attached",
                        user.user_name
                    ),
                )
            };

            reports.push(make_report(
                "iam_aws_attached_policy_no_administrative_privileges",
                "Ensure IAM users and roles do not have AdministratorAccess attached",
                Severity::High,
                status,
                &user.user_name,
                &user.arn,
                "us-east-1",
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        // Check roles
        for role in &iam.roles {
            let has_admin = role
                .attached_policies
                .iter()
                .any(|p| p == ADMIN_POLICY_ARN);

            let (status, msg) = if has_admin {
                (
                    Status::Fail,
                    format!(
                        "Role {} has AdministratorAccess policy attached",
                        role.role_name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Role {} does not have AdministratorAccess policy attached",
                        role.role_name
                    ),
                )
            };

            reports.push(make_report(
                "iam_aws_attached_policy_no_administrative_privileges",
                "Ensure IAM users and roles do not have AdministratorAccess attached",
                Severity::High,
                status,
                &role.role_name,
                &role.arn,
                "us-east-1",
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
