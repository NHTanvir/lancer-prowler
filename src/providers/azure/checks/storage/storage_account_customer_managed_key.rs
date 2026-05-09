use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::storage::make_report;
use crate::providers::azure::services::storage::StorageService;

pub struct StorageAccountCustomerManagedKey;

impl Check for StorageAccountCustomerManagedKey {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_account_customer_managed_key".to_string(),
            name: "Ensure Storage Accounts are encrypted with customer-managed keys".to_string(),
            description: "Using customer-managed keys for storage account encryption provides \
                greater control over key lifecycle management and auditability."
                .to_string(),
            severity: Severity::Medium,
            service: "storage".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "3.9".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-12".to_string(),
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

            let (status, msg) = if account.encryption_key_source != "Microsoft.Storage" {
                (
                    Status::Pass,
                    format!(
                        "Storage account {} uses customer-managed key encryption ({})",
                        account.name, account.encryption_key_source
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Storage account {} uses Microsoft-managed keys instead of customer-managed keys",
                        account.name
                    ),
                )
            };

            reports.push(make_report(
                "storage_account_customer_managed_key",
                "Ensure Storage Accounts are encrypted with customer-managed keys",
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
