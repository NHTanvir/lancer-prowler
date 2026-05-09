use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::keyvault::make_report;
use crate::providers::azure::services::keyvault::KeyVaultService;

pub struct KeyVaultPublicNetworkAccessDisabled;

impl Check for KeyVaultPublicNetworkAccessDisabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "keyvault_public_network_access_disabled".to_string(),
            name: "Ensure that Azure Key Vault disables public network access".to_string(),
            description: "Disabling public network access for Key Vaults restricts access to \
                private endpoints only, reducing the attack surface."
                .to_string(),
            severity: Severity::Medium,
            service: "keyvault".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "8.7".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-7".to_string(),
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

            let (status, msg) = if vault.public_network_access == "Disabled" {
                (
                    Status::Pass,
                    format!("Key Vault {} has public network access disabled", vault.name),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Key Vault {} has public network access enabled (expected Disabled)",
                        vault.name
                    ),
                )
            };

            reports.push(make_report(
                "keyvault_public_network_access_disabled",
                "Ensure that Azure Key Vault disables public network access",
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
