use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::storage::make_report;
use crate::providers::azure::services::storage::StorageService;

pub struct StorageAccountSecureTransferRequired;

impl Check for StorageAccountSecureTransferRequired {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_account_secure_transfer_required".to_string(),
            name: "Ensure that 'Secure transfer required' is set to 'Enabled' for Storage Accounts".to_string(),
            description: "Enabling secure transfer ensures that storage account data in transit \
                is always sent over HTTPS, preventing man-in-the-middle attacks."
                .to_string(),
            severity: Severity::High,
            service: "storage".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "3.1".to_string(),
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

            let (status, msg) = if account.https_traffic_only {
                (
                    Status::Pass,
                    format!("Storage account {} has secure transfer (HTTPS only) enabled", account.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Storage account {} does not require secure transfer (HTTPS only)", account.name),
                )
            };

            reports.push(make_report(
                "storage_account_secure_transfer_required",
                "Ensure that 'Secure transfer required' is set to 'Enabled' for Storage Accounts",
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
