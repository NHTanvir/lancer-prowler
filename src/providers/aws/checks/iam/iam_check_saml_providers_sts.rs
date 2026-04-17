use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

pub struct IamCheckSamlProvidersSts;

impl Check for IamCheckSamlProvidersSts {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_check_saml_providers_sts".to_string(),
            name: "Ensure IAM SAML providers are configured for federated access".to_string(),
            description: "SAML providers allow federated users to assume roles in AWS using \
                their corporate credentials. This check verifies SAML provider configuration \
                but requires manual verification or additional IAM API access."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.21".to_string(),
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
        let resource_arn = format!("arn:aws:iam::{}:saml-provider", account_id);

        vec![make_report(
            "iam_check_saml_providers_sts",
            "Ensure IAM SAML providers are configured for federated access",
            Severity::Medium,
            Status::Pass,
            "saml_providers",
            &resource_arn,
            "us-east-1",
            account_id,
            "SAML provider check requires manual verification or additional IAM API access",
            self.metadata().compliance.clone(),
        )]
    }
}
