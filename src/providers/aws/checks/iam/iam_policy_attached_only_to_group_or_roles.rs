use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamPolicyAttachedOnlyToGroupOrRoles;

impl Check for IamPolicyAttachedOnlyToGroupOrRoles {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_policy_attached_only_to_group_or_roles".to_string(),
            name: "Ensure IAM policies are attached only to groups or roles".to_string(),
            description: "By default, IAM users, groups, and roles have no access to AWS \
                resources. IAM policies are the means by which privileges are granted to users, \
                groups, or roles. It is recommended that IAM policies be applied directly to \
                groups and roles but not users."
                .to_string(),
            severity: Severity::Low,
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

        for user in &iam.users {
            let (status, msg) = if !user.attached_policies.is_empty() {
                (
                    Status::Fail,
                    format!(
                        "User {} has {} policy/policies attached directly (should be via groups/roles only): {}",
                        user.user_name,
                        user.attached_policies.len(),
                        user.attached_policies.join(", ")
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "User {} has no directly attached policies",
                        user.user_name
                    ),
                )
            };

            reports.push(make_report(
                "iam_policy_attached_only_to_group_or_roles",
                "Ensure IAM policies are attached only to groups or roles",
                Severity::Low,
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
