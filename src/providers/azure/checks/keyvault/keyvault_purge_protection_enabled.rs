use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::keyvault::make_report;
use crate::providers::azure::services::keyvault::KeyVaultService;

pub struct KeyVaultPurgeProtectionEnabled;

impl Check for KeyVaultPurgeProtectionEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "keyvault_purge_protection_enabled".to_string(),
            name: "Ensure that Azure Key Vault has purge protection enabled".to_string(),
            description: "Purge protection prevents permanent deletion of Key Vault objects \
                by malicious insiders or accidental operations during the soft-delete retention period."
                .to_string(),
            severity: Severity::High,
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

            let (status, msg) = if vault.purge_protection_enabled {
                (
                    Status::Pass,
                    format!("Key Vault {} has purge protection enabled", vault.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Key Vault {} does not have purge protection enabled", vault.name),
                )
            };

            reports.push(make_report(
                "keyvault_purge_protection_enabled",
                "Ensure that Azure Key Vault has purge protection enabled",
                Severity::High,
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
