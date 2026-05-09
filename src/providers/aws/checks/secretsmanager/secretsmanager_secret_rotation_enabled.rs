use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::secretsmanager::make_report;
use crate::providers::aws::services::secretsmanager::SecretsManagerService;

pub struct SecretsManagerSecretRotationEnabled;

impl Check for SecretsManagerSecretRotationEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "secretsmanager_secret_rotation_enabled".to_string(),
            name: "Ensure Secrets Manager secrets have rotation enabled".to_string(),
            description: "AWS Secrets Manager can automatically rotate secrets. \
                Rotation reduces the risk of compromised credentials by regularly \
                replacing them with new ones."
                .to_string(),
            severity: Severity::Medium,
            service: "secretsmanager".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_1.4".to_string(),
                    control_id: "1.19".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-2".to_string(),
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
            let (status, msg) = if !secret.rotation_enabled {
                (
                    Status::Fail,
                    format!("Secret {} does not have rotation enabled", secret.name),
                )
            } else {
                (
                    Status::Pass,
                    format!("Secret {} has rotation enabled", secret.name),
                )
            };

            reports.push(make_report(
                "secretsmanager_secret_rotation_enabled",
                "Ensure Secrets Manager secrets have rotation enabled",
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
