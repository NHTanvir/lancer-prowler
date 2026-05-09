use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::storage::make_report;
use crate::providers::azure::services::storage::StorageService;

pub struct StorageAccountBlobSoftDeleteEnabled;

impl Check for StorageAccountBlobSoftDeleteEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_account_blob_soft_delete_enabled".to_string(),
            name: "Ensure Soft Delete is enabled for Azure Storage blob".to_string(),
            description: "Enabling blob soft delete allows recovery of accidentally deleted blobs \
                within a configurable retention period."
                .to_string(),
            severity: Severity::Medium,
            service: "storage".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "3.10".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SI-12".to_string(),
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

            let (status, msg) = if account.blob_soft_delete_enabled {
                (
                    Status::Pass,
                    format!("Storage account {} has blob soft delete enabled", account.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Storage account {} does not have blob soft delete enabled", account.name),
                )
            };

            reports.push(make_report(
                "storage_account_blob_soft_delete_enabled",
                "Ensure Soft Delete is enabled for Azure Storage blob",
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
