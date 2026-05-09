use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

const SUPPORT_POLICY_ARN: &str = "arn:aws:iam::aws:policy/AWSSupportAccess";

pub struct IamSupportRoleCreated;

impl Check for IamSupportRoleCreated {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_support_role_created".to_string(),
            name: "Ensure a support role has been created to manage incidents with AWS Support"
                .to_string(),
            description: "AWS provides a support center that can be used for incident notification \
                and response, as well as technical support and customer services. An IAM role with \
                AWSSupportAccess managed policy should be created to allow authorized users to \
                manage incidents with AWS Support."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.17".to_string(),
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
        let resource_arn = format!("arn:aws:iam::{}:role/support", account_id);

        let support_role_exists = iam.roles.iter().any(|r| {
            r.attached_policies
                .iter()
                .any(|p| p == SUPPORT_POLICY_ARN)
        });

        let (status, msg) = if support_role_exists {
            (
                Status::Pass,
                "A role with AWSSupportAccess policy exists".to_string(),
            )
        } else {
            (
                Status::Fail,
                "No role with AWSSupportAccess policy found — create a support role".to_string(),
            )
        };

        vec![make_report(
            "iam_support_role_created",
            "Ensure a support role has been created to manage incidents with AWS Support",
            Severity::Medium,
            status,
            "AWSSupportAccess",
            &resource_arn,
            "us-east-1",
            account_id,
            &msg,
            self.metadata().compliance.clone(),
        )]
    }
}
