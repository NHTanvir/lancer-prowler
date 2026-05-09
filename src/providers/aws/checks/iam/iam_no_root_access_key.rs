use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamNoRootAccessKey;

impl Check for IamNoRootAccessKey {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_no_root_access_key".to_string(),
            name: "Ensure no root user account access key exists".to_string(),
            description: "The root user account is the most privileged user in an AWS account. \
                Access keys for the root user account should not be created to avoid long-term \
                credential compromise."
                .to_string(),
            severity: Severity::Critical,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.4".to_string(),
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

        let root_entry = iam
            .credential_report
            .iter()
            .find(|e| e.user == "<root_account>");

        match root_entry {
            None => vec![make_report(
                "iam_no_root_access_key",
                "Ensure no root user account access key exists",
                Severity::Critical,
                Status::Unknown,
                "root_account",
                &resource_arn,
                "us-east-1",
                account_id,
                "Root account entry not found in credential report",
                self.metadata().compliance.clone(),
            )],
            Some(root) => {
                let has_active_key =
                    root.access_key_1_active || root.access_key_2_active;
                let (status, msg) = if has_active_key {
                    (
                        Status::Fail,
                        "Root account has active access key(s) — remove them immediately"
                            .to_string(),
                    )
                } else {
                    (
                        Status::Pass,
                        "Root account has no active access keys".to_string(),
                    )
                };
                vec![make_report(
                    "iam_no_root_access_key",
                    "Ensure no root user account access key exists",
                    Severity::Critical,
                    status,
                    "root_account",
                    &resource_arn,
                    "us-east-1",
                    account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                )]
            }
        }
    }
}
