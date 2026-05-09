use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::storage::make_report;
use crate::providers::azure::services::storage::StorageService;

pub struct StorageAccountInfrastructureEncryptionEnabled;

impl Check for StorageAccountInfrastructureEncryptionEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_account_infrastructure_encryption_enabled".to_string(),
            name: "Ensure that infrastructure encryption is enabled for Azure Storage Account".to_string(),
            description: "Infrastructure encryption provides a second layer of encryption for \
                storage account data using platform-managed keys."
                .to_string(),
            severity: Severity::Medium,
            service: "storage".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "3.11".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-28".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<StorageService>() {
            Some(s) => s,
            None => return vec![],
        };

        let subscription_id = &svc.subscription_id;
        let mut reports = Vec::new();

        for account in &svc.accounts {
            let resource_arn = format!(
                "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Storage/storageAccounts/{}",
                subscription_id, account.resource_group, account.name
            );

            let (status, msg) = if account.infrastructure_encryption {
                (
                    Status::Pass,
                    format!("Storage account {} has infrastructure encryption enabled", account.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Storage account {} does not have infrastructure encryption enabled", account.name),
                )
            };

            reports.push(make_report(
                "storage_account_infrastructure_encryption_enabled",
                "Ensure that infrastructure encryption is enabled for Azure Storage Account",
                Severity::Medium,
                status,
                &account.name,
                &resource_arn,
                &account.location,
                subscription_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
