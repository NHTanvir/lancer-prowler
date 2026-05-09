use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::keyvault::make_report;
use crate::providers::azure::services::keyvault::KeyVaultService;

pub struct KeyVaultPremiumSku;

impl Check for KeyVaultPremiumSku {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "keyvault_premium_sku".to_string(),
            name: "Ensure Azure Key Vault uses the Premium SKU for HSM-backed keys".to_string(),
            description: "The Premium SKU enables hardware security module (HSM)-backed keys, \
                providing stronger cryptographic guarantees for key protection."
                .to_string(),
            severity: Severity::Low,
            service: "keyvault".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
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

            let (status, msg) = if vault.sku_name == "premium" {
                (
                    Status::Pass,
                    format!("Key Vault {} uses the premium SKU (HSM-backed keys supported)", vault.name),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Key Vault {} uses the '{}' SKU; premium SKU recommended for HSM-backed keys",
                        vault.name, vault.sku_name
                    ),
                )
            };

            reports.push(make_report(
                "keyvault_premium_sku",
                "Ensure Azure Key Vault uses the Premium SKU for HSM-backed keys",
                Severity::Low,
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
