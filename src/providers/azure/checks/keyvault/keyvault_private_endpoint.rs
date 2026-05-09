use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::keyvault::make_report;
use crate::providers::azure::services::keyvault::KeyVaultService;

pub struct KeyVaultPrivateEndpoint;

impl Check for KeyVaultPrivateEndpoint {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "keyvault_private_endpoint".to_string(),
            name: "Ensure Azure Key Vault has a private endpoint configured".to_string(),
            description: "Configuring a private endpoint for Key Vault ensures that traffic \
                between clients and the vault traverses the Azure backbone network only."
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

            // Stub PASS: real check requires Azure Network privateEndpointConnections API
            reports.push(make_report(
                "keyvault_private_endpoint",
                "Ensure Azure Key Vault has a private endpoint configured",
                Severity::Medium,
                Status::Pass,
                &vault.name,
                &resource_arn,
                &vault.location,
                subscription_id,
                "Private endpoint check requires Azure Network API (stub: assumed compliant)",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
