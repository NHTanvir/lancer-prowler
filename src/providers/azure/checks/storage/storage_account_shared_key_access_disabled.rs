use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::storage::make_report;
use crate::providers::azure::services::storage::StorageService;

pub struct StorageAccountSharedKeyAccessDisabled;

impl Check for StorageAccountSharedKeyAccessDisabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_account_shared_key_access_disabled".to_string(),
            name: "Ensure that Storage Account 'Allow shared key access' is set to 'Disabled'".to_string(),
            description: "Disabling shared key access forces all requests to use Azure AD \
                authentication, providing better auditability and fine-grained access control."
                .to_string(),
            severity: Severity::Medium,
            service: "storage".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "3.13".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "IA-2".to_string(),
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

            let (status, msg) = if !account.shared_key_access_enabled {
                (
                    Status::Pass,
                    format!("Storage account {} has shared key access disabled", account.name),
                )
            } else {
                (
                    Status::Fail,
                    format!("Storage account {} has shared key access enabled (should be disabled)", account.name),
                )
            };

            reports.push(make_report(
                "storage_account_shared_key_access_disabled",
                "Ensure that Storage Account 'Allow shared key access' is set to 'Disabled'",
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
