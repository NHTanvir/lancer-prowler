use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::storage::make_report;
use crate::providers::azure::services::storage::StorageService;

pub struct StorageAccountVersioningEnabled;

impl Check for StorageAccountVersioningEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_account_versioning_enabled".to_string(),
            name: "Ensure that blob versioning is enabled in Azure Storage Account".to_string(),
            description: "Blob versioning automatically maintains previous versions of a blob, \
                enabling data recovery from accidental deletions or overwrites."
                .to_string(),
            severity: Severity::Low,
            service: "storage".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "3.7".to_string(),
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

            let (status, msg) = if account.versioning_enabled {
                (
                    Status::Pass,
                    format!("Storage account {} has blob versioning enabled", account.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Storage account {} does not have blob versioning enabled", account.name),
                )
            };

            reports.push(make_report(
                "storage_account_versioning_enabled",
                "Ensure that blob versioning is enabled in Azure Storage Account",
                Severity::Low,
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
