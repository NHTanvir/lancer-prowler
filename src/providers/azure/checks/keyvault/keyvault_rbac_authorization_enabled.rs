use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::keyvault::make_report;
use crate::providers::azure::services::keyvault::KeyVaultService;

pub struct KeyVaultRbacAuthorizationEnabled;

impl Check for KeyVaultRbacAuthorizationEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "keyvault_rbac_authorization_enabled".to_string(),
            name: "Ensure Azure Key Vault uses RBAC for authorization".to_string(),
            description: "Using Azure RBAC for Key Vault authorization provides centralized \
                access management and fine-grained permissions over legacy access policies."
                .to_string(),
            severity: Severity::Medium,
            service: "keyvault".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "8.3".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-2".to_string(),
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

            let (status, msg) = if vault.rbac_authorization {
                (
                    Status::Pass,
                    format!("Key Vault {} uses RBAC authorization", vault.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Key Vault {} does not use RBAC authorization (uses vault access policies)", vault.name),
                )
            };

            reports.push(make_report(
                "keyvault_rbac_authorization_enabled",
                "Ensure Azure Key Vault uses RBAC for authorization",
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
