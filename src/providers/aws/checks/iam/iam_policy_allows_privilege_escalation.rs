use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::{make_report, policy_grants_any_action_on_star};
use crate::providers::aws::services::iam::IamService;

/// IAM actions that can lead to privilege escalation when granted with Resource:*.
const ESCALATION_ACTIONS: &[&str] = &[
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
];

pub struct IamPolicyAllowsPrivilegeEscalation;

impl Check for IamPolicyAllowsPrivilegeEscalation {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_policy_allows_privilege_escalation".to_string(),
            name: "Ensure IAM policies do not allow privilege escalation".to_string(),
            description: "Certain IAM actions, when granted with Effect:Allow and Resource:*, \
                allow a user to escalate their own privileges. These include actions like \
                iam:AttachUserPolicy, iam:CreatePolicyVersion, iam:PassRole, etc."
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

            let has_escalation =
                policy_grants_any_action_on_star(&policy.document, ESCALATION_ACTIONS);

            let (status, msg) = if has_escalation {
                (
                    Status::Fail,
                    format!(
                        "Customer-managed policy {} grants one or more privilege escalation \
                        actions (e.g., iam:AttachUserPolicy, iam:PassRole) with Resource:*",
                        policy.policy_name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Policy {} does not grant privilege escalation actions with Resource:*",
                        policy.policy_name
                    ),
                )
            };

            reports.push(make_report(
                "iam_policy_allows_privilege_escalation",
                "Ensure IAM policies do not allow privilege escalation",
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
