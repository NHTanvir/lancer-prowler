use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::{make_report, policy_grants_action_on_star};
use crate::providers::aws::services::iam::IamService;

pub struct IamPolicyNoFullAccessToCloudTrail;

impl Check for IamPolicyNoFullAccessToCloudTrail {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_policy_no_full_access_to_cloudtrail".to_string(),
            name: "Ensure IAM policies do not grant full access to CloudTrail".to_string(),
            description: "IAM policies that grant full CloudTrail access allow users to \
                delete trails, stop logging, or otherwise tamper with audit logs."
                .to_string(),
            severity: Severity::High,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.6".to_string(),
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

            let has_full_cloudtrail = policy_grants_action_on_star(&policy.document, "cloudtrail:");

            let (status, msg) = if has_full_cloudtrail {
                (
                    Status::Fail,
                    format!(
                        "Policy {} grants full or broad CloudTrail access (Effect:Allow cloudtrail:* Resource:*)",
                        policy.policy_name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Policy {} does not grant full CloudTrail access",
                        policy.policy_name
                    ),
                )
            };

            reports.push(make_report(
                "iam_policy_no_full_access_to_cloudtrail",
                "Ensure IAM policies do not grant full access to CloudTrail",
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
