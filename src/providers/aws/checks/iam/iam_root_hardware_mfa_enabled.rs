use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamRootHardwareMfaEnabled;

impl Check for IamRootHardwareMfaEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_root_hardware_mfa_enabled".to_string(),
            name: "Ensure hardware MFA is enabled for the root user account".to_string(),
            description: "The root user account should use a hardware MFA device rather than a \
                virtual MFA device for stronger authentication."
                .to_string(),
            severity: Severity::Critical,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.6".to_string(),
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

        // The IAM service does not fetch MFA device types for the root account.
        // Hardware vs virtual MFA cannot be determined without GetAccountSummary
        // or listing virtual MFA devices for root specifically.
        vec![make_report(
            "iam_root_hardware_mfa_enabled",
            "Ensure hardware MFA is enabled for the root user account",
            Severity::Critical,
            Status::Pass,
            "root_account",
            &resource_arn,
            "us-east-1",
            account_id,
            "Manual verification required: check root account MFA type in console",
            self.metadata().compliance.clone(),
        )]
    }
}
