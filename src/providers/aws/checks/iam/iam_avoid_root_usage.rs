use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::{make_report, within_last_days};
use crate::providers::aws::services::iam::IamService;

pub struct IamAvoidRootUsage;

impl Check for IamAvoidRootUsage {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_avoid_root_usage".to_string(),
            name: "Avoid the use of the root user account".to_string(),
            description: "The use of the root user account should be avoided for everyday tasks. \
                If the root account has been used within the last 90 days, this is a finding."
                .to_string(),
            severity: Severity::High,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.7".to_string(),
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
                "iam_avoid_root_usage",
                "Avoid the use of the root user account",
                Severity::High,
                Status::Unknown,
                "root_account",
                &resource_arn,
                "us-east-1",
                account_id,
                "Root account entry not found in credential report",
                self.metadata().compliance.clone(),
            )],
            Some(root) => {
                let last_used = &root.password_last_used;
                let used_recently = within_last_days(last_used, 90);
                let (status, msg) = if used_recently {
                    (
                        Status::Fail,
                        format!(
                            "Root account was last used on {} (within 90 days)",
                            last_used
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        if last_used == "N/A" || last_used.is_empty() {
                            "Root account password has never been used".to_string()
                        } else {
                            format!(
                                "Root account last used on {} (more than 90 days ago)",
                                last_used
                            )
                        },
                    )
                };
                vec![make_report(
                    "iam_avoid_root_usage",
                    "Avoid the use of the root user account",
                    Severity::High,
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
