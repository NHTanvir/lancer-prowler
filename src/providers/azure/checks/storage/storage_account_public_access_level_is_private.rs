use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::storage::make_report;
use crate::providers::azure::services::storage::StorageService;

pub struct StorageAccountPublicAccessLevelIsPrivate;

impl Check for StorageAccountPublicAccessLevelIsPrivate {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_account_public_access_level_is_private".to_string(),
            name: "Ensure that 'Allow Blob Public Access' is set to 'Disabled' for Storage Accounts".to_string(),
            description: "Disabling blob public access ensures that blobs are not publicly \
                accessible from the internet without authorization."
                .to_string(),
            severity: Severity::Critical,
            service: "storage".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "3.5".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-3".to_string(),
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

            let (status, msg) = if !account.blob_public_access {
                (
                    Status::Pass,
                    format!("Storage account {} has blob public access disabled", account.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Storage account {} allows blob public access", account.name),
                )
            };

            reports.push(make_report(
                "storage_account_public_access_level_is_private",
                "Ensure that 'Allow Blob Public Access' is set to 'Disabled' for Storage Accounts",
                Severity::Critical,
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
