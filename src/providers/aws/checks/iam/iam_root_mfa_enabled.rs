use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamRootMfaEnabled;

impl Check for IamRootMfaEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_root_mfa_enabled".to_string(),
            name: "Ensure MFA is enabled for the root user account".to_string(),
            description: "The root user account is the most privileged user in an AWS account. \
                MFA adds an extra layer of protection on top of a username and password."
                .to_string(),
            severity: Severity::Critical,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.5".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "IA-2".to_string(),
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
                "iam_root_mfa_enabled",
                "Ensure MFA is enabled for the root user account",
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
                let (status, msg) = if root.mfa_active {
                    (
                        Status::Pass,
                        "MFA is enabled for the root account".to_string(),
                    )
                } else {
                    (
                        Status::Fail,
                        "MFA is NOT enabled for the root account".to_string(),
                    )
                };
                vec![make_report(
                    "iam_root_mfa_enabled",
                    "Ensure MFA is enabled for the root user account",
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
