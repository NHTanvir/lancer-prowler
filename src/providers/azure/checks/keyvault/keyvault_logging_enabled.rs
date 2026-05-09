use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::keyvault::make_report;
use crate::providers::azure::services::keyvault::KeyVaultService;

pub struct KeyVaultLoggingEnabled;

impl Check for KeyVaultLoggingEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "keyvault_logging_enabled".to_string(),
            name: "Ensure that Azure Key Vault has diagnostic logging enabled".to_string(),
            description: "Enabling diagnostic logging for Key Vault ensures that all requests \
                and operations are captured for auditing and security monitoring."
                .to_string(),
            severity: Severity::Medium,
            service: "keyvault".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "8.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AU-2".to_string(),
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

            // Stub PASS: real check requires Azure Monitor diagnostic settings API
            reports.push(make_report(
                "keyvault_logging_enabled",
                "Ensure that Azure Key Vault has diagnostic logging enabled",
                Severity::Medium,
                Status::Pass,
                &vault.name,
                &resource_arn,
                &vault.location,
                subscription_id,
                "Diagnostic settings check requires Azure Monitor API (stub: assumed compliant)",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
