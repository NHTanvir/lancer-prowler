use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamUserMfaEnabledConsoleAccess;

impl Check for IamUserMfaEnabledConsoleAccess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_user_mfa_enabled_console_access".to_string(),
            name: "Ensure MFA is enabled for all IAM users that have a console password".to_string(),
            description: "Multi-Factor Authentication (MFA) adds an extra layer of protection \
                on top of a username and password. All users with console access should have MFA enabled."
                .to_string(),
            severity: Severity::High,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.10".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "IA-2".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-2".to_string(),
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

        for entry in &iam.credential_report {
            // Skip root — handled by iam_root_mfa_enabled
            if entry.user == "<root_account>" {
                continue;
            }

            // Determine if the user has console access
            let has_console_access = entry.password_enabled != "false"
                && entry.password_enabled != "not_supported";

            // Find the matching IAM user for MFA devices
            let mfa_devices = iam
                .users
                .iter()
                .find(|u| u.user_name == entry.user)
                .map(|u| u.mfa_devices.len())
                .unwrap_or(0);

            let user_arn = iam
                .users
                .iter()
                .find(|u| u.user_name == entry.user)
                .map(|u| u.arn.clone())
                .unwrap_or_else(|| format!("arn:aws:iam::{}:user/{}", account_id, entry.user));

            let (status, msg) = if !has_console_access {
                (
                    Status::Pass,
                    format!(
                        "User {} does not have console access — MFA not required",
                        entry.user
                    ),
                )
            } else if mfa_devices > 0 {
                (
                    Status::Pass,
                    format!(
                        "User {} has MFA enabled ({} device(s))",
                        entry.user, mfa_devices
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "User {} has console access but NO MFA device configured",
                        entry.user
                    ),
                )
            };

            reports.push(make_report(
                "iam_user_mfa_enabled_console_access",
                "Ensure MFA is enabled for all IAM users that have a console password",
                Severity::High,
                status,
                &entry.user,
                &user_arn,
                "us-east-1",
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
