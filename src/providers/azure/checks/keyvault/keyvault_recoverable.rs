use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::keyvault::make_report;
use crate::providers::azure::services::keyvault::KeyVaultService;

pub struct KeyVaultRecoverable;

impl Check for KeyVaultRecoverable {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "keyvault_recoverable".to_string(),
            name: "Ensure Azure Key Vault is recoverable (soft delete and purge protection both enabled)".to_string(),
            description: "A Key Vault is fully recoverable only when both soft delete and purge \
                protection are enabled, protecting against accidental or malicious permanent deletion."
                .to_string(),
            severity: Severity::Medium,
            service: "keyvault".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "8.5".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SI-12".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<KeyVaultService>() {
            Some(s) => s,
            None => return vec![],
        };

        let subscription_id = &svc.subscription_id;
        let mut reports = Vec::new();

        for vault in &svc.vaults {
            let resource_arn = format!(
                "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.KeyVault/vaults/{}",
                subscription_id, vault.resource_group, vault.name
            );

            let (status, msg) = if vault.soft_delete_enabled && vault.purge_protection_enabled {
                (
                    Status::Pass,
                    format!(
                        "Key Vault {} is fully recoverable (soft delete and purge protection both enabled)",
                        vault.name
                    ),
                )
            } else {
                let missing: Vec<&str> = [
                    (!vault.soft_delete_enabled).then_some("soft delete"),
                    (!vault.purge_protection_enabled).then_some("purge protection"),
                ]
                .into_iter()
                .flatten()
                .collect();
                (
                    Status::Fail,
                    format!(
                        "Key Vault {} is not fully recoverable — missing: {}",
                        vault.name,
                        missing.join(", ")
                    ),
                )
            };

            reports.push(make_report(
                "keyvault_recoverable",
                "Ensure Azure Key Vault is recoverable (soft delete and purge protection both enabled)",
                Severity::Medium,
                status,
                &vault.name,
                &resource_arn,
                &vault.location,
                subscription_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
