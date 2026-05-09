use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::secretsmanager::make_report;
use crate::providers::aws::services::secretsmanager::SecretsManagerService;

pub struct SecretsManagerSecretEncryptedWithCmk;

impl Check for SecretsManagerSecretEncryptedWithCmk {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "secretsmanager_secret_encrypted_with_cmk".to_string(),
            name: "Ensure Secrets Manager secrets are encrypted with a customer-managed KMS key"
                .to_string(),
            description: "Secrets Manager secrets should be encrypted with a customer-managed \
                KMS key (CMK) rather than the AWS-managed default key, providing greater \
                control over encryption key management."
                .to_string(),
            severity: Severity::Medium,
            service: "secretsmanager".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-28".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<SecretsManagerService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for secret in &svc.secrets {
            let (status, msg) = if secret.kms_key_id.is_none() {
                (
                    Status::Fail,
                    format!(
                        "Secret {} is not encrypted with a customer-managed KMS key (using AWS default key)",
                        secret.name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Secret {} is encrypted with CMK: {}",
                        secret.name,
                        secret.kms_key_id.as_deref().unwrap_or("")
                    ),
                )
            };

            reports.push(make_report(
                "secretsmanager_secret_encrypted_with_cmk",
                "Ensure Secrets Manager secrets are encrypted with a customer-managed KMS key",
                Severity::Medium,
                status,
                &secret.name,
                &secret.arn,
                &secret.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
