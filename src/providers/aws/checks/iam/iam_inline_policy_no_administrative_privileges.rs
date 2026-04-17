use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::{make_report, policy_has_admin_access};
use crate::providers::aws::services::iam::IamService;

pub struct IamInlinePolicyNoAdministrativePrivileges;

impl Check for IamInlinePolicyNoAdministrativePrivileges {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_inline_policy_no_administrative_privileges".to_string(),
            name: "Ensure IAM inline policies do not grant administrative privileges".to_string(),
            description: "Inline policies that grant full administrative access (Action:*, Resource:*) \
                should not be attached to IAM users, roles, or groups."
                .to_string(),
            severity: Severity::Critical,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.15".to_string(),
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
            for policy_name in &user.inline_policies {
                // Inline policy names are stored — documents are not pre-fetched.
                // We flag the presence and note that document-level check is limited.
                // The policy_has_admin_access will return false on empty string, so we report
                // the existence of inline policies as a concern.
                let resource_id = format!("{}/{}", user.user_name, policy_name);
                reports.push(make_report(
                    "iam_inline_policy_no_administrative_privileges",
                    "Ensure IAM inline policies do not grant administrative privileges",
                    Severity::Critical,
                    Status::Fail,
                    &resource_id,
                    &user.arn,
                    "us-east-1",
                    account_id,
                    &format!(
                        "User {} has inline policy '{}' — inline policies should not be used; \
                        verify it does not grant admin privileges",
                        user.user_name, policy_name
                    ),
                    self.metadata().compliance.clone(),
                ));
            }
            if user.inline_policies.is_empty() {
                reports.push(make_report(
                    "iam_inline_policy_no_administrative_privileges",
                    "Ensure IAM inline policies do not grant administrative privileges",
                    Severity::Critical,
                    Status::Pass,
                    &user.user_name,
                    &user.arn,
                    "us-east-1",
                    account_id,
                    &format!("User {} has no inline policies", user.user_name),
                    self.metadata().compliance.clone(),
                ));
            }
        }

        // Check roles
        for role in &iam.roles {
            for policy_name in &role.inline_policies {
                let resource_id = format!("{}/{}", role.role_name, policy_name);
                reports.push(make_report(
                    "iam_inline_policy_no_administrative_privileges",
                    "Ensure IAM inline policies do not grant administrative privileges",
                    Severity::Critical,
                    Status::Fail,
                    &resource_id,
                    &role.arn,
                    "us-east-1",
                    account_id,
                    &format!(
                        "Role {} has inline policy '{}' — verify it does not grant admin privileges",
                        role.role_name, policy_name
                    ),
                    self.metadata().compliance.clone(),
                ));
            }
        }

        // Check groups
        for group in &iam.groups {
            for policy_name in &group.inline_policies {
                let resource_id = format!("{}/{}", group.group_name, policy_name);
                reports.push(make_report(
                    "iam_inline_policy_no_administrative_privileges",
                    "Ensure IAM inline policies do not grant administrative privileges",
                    Severity::Critical,
                    Status::Fail,
                    &resource_id,
                    &group.arn,
                    "us-east-1",
                    account_id,
                    &format!(
                        "Group {} has inline policy '{}' — verify it does not grant admin privileges",
                        group.group_name, policy_name
                    ),
                    self.metadata().compliance.clone(),
                ));
            }
        }

        // Also check customer-managed policies using the full document
        for policy in &iam.policies {
            if !policy.is_aws_managed && policy_has_admin_access(&policy.document) {
                reports.push(make_report(
                    "iam_inline_policy_no_administrative_privileges",
                    "Ensure IAM inline policies do not grant administrative privileges",
                    Severity::Critical,
                    Status::Fail,
                    &policy.policy_name,
                    &policy.arn,
                    "us-east-1",
                    account_id,
                    &format!(
                        "Policy {} grants administrative privileges (Effect:Allow Action:* Resource:*)",
                        policy.policy_name
                    ),
                    self.metadata().compliance.clone(),
                ));
            }
        }

        reports
    }
}
