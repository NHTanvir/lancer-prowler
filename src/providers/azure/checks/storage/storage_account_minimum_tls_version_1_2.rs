use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::storage::make_report;
use crate::providers::azure::services::storage::StorageService;

pub struct StorageAccountMinimumTlsVersion12;

impl Check for StorageAccountMinimumTlsVersion12 {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_account_minimum_tls_version_1_2".to_string(),
            name: "Ensure the minimum TLS version for Storage Accounts is TLS 1.2".to_string(),
            description: "Setting the minimum TLS version to 1.2 ensures that all connections to \
                the storage account use the current recommended TLS standard."
                .to_string(),
            severity: Severity::High,
            service: "storage".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "3.12".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-8".to_string(),
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

            let (status, msg) = if account.tls_version == "TLS1_2" {
                (
                    Status::Pass,
                    format!("Storage account {} has minimum TLS version set to TLS1_2", account.name),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Storage account {} has minimum TLS version set to {} (expected TLS1_2)",
                        account.name, account.tls_version
                    ),
                )
            };

            reports.push(make_report(
                "storage_account_minimum_tls_version_1_2",
                "Ensure the minimum TLS version for Storage Accounts is TLS 1.2",
                Severity::High,
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
