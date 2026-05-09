use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::{make_report, policy_grants_action_on_star};
use crate::providers::aws::services::iam::IamService;

pub struct IamPolicyNoFullAccessToKms;

impl Check for IamPolicyNoFullAccessToKms {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_policy_no_full_access_to_kms".to_string(),
            name: "Ensure IAM policies do not grant full access to KMS".to_string(),
            description: "IAM policies that grant full KMS access allow users to delete keys, \
                disable keys, or use keys to decrypt sensitive data."
                .to_string(),
            severity: Severity::High,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.7".to_string(),
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

            let has_full_kms = policy_grants_action_on_star(&policy.document, "kms:");

            let (status, msg) = if has_full_kms {
                (
                    Status::Fail,
                    format!(
                        "Policy {} grants full or broad KMS access (Effect:Allow kms:* Resource:*)",
                        policy.policy_name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Policy {} does not grant full KMS access",
                        policy.policy_name
                    ),
                )
            };

            reports.push(make_report(
                "iam_policy_no_full_access_to_kms",
                "Ensure IAM policies do not grant full access to KMS",
                Severity::High,
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
