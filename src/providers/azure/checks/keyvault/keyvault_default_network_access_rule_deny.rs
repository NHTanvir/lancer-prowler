use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::keyvault::make_report;
use crate::providers::azure::services::keyvault::KeyVaultService;

pub struct KeyVaultDefaultNetworkAccessRuleDeny;

impl Check for KeyVaultDefaultNetworkAccessRuleDeny {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "keyvault_default_network_access_rule_deny".to_string(),
            name: "Ensure the Azure Key Vault default network access rule is set to Deny".to_string(),
            description: "Setting the Key Vault default network access rule to Deny restricts \
                access to explicitly allowed networks and IP ranges only."
                .to_string(),
            severity: Severity::High,
            service: "keyvault".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "8.6".to_string(),
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

            let (status, msg) = if vault.network_default_action == "Deny" {
                (
                    Status::Pass,
                    format!("Key Vault {} has default network access rule set to Deny", vault.name),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Key Vault {} has default network access rule set to Allow (expected Deny)",
                        vault.name
                    ),
                )
            };

            reports.push(make_report(
                "keyvault_default_network_access_rule_deny",
                "Ensure the Azure Key Vault default network access rule is set to Deny",
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
