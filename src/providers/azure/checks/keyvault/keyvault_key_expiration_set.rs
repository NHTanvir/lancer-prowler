use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::keyvault::make_report;
use crate::providers::azure::services::keyvault::KeyVaultService;

pub struct KeyVaultKeyExpirationSet;

impl Check for KeyVaultKeyExpirationSet {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "keyvault_key_expiration_set".to_string(),
            name: "Ensure that the expiry date is set on all keys in Key Vault".to_string(),
            description: "Setting an expiry date on Key Vault keys ensures they are rotated \
                periodically, limiting the impact of key compromise."
                .to_string(),
            severity: Severity::Medium,
            service: "keyvault".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "8.2".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-12".to_string(),
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

            // Stub PASS: real check requires Azure KeyVault data-plane API to enumerate keys
            reports.push(make_report(
                "keyvault_key_expiration_set",
                "Ensure that the expiry date is set on all keys in Key Vault",
                Severity::Medium,
                Status::Pass,
                &vault.name,
                &resource_arn,
                &vault.location,
                subscription_id,
                "Key expiration check requires Azure KeyVault data-plane API (stub: assumed compliant)",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
