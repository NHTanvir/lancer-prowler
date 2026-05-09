use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::azure::checks::storage::make_report;
use crate::providers::azure::services::storage::StorageService;

pub struct StorageAccountDefaultNetworkAccessRuleDeny;

impl Check for StorageAccountDefaultNetworkAccessRuleDeny {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "storage_account_default_network_access_rule_deny".to_string(),
            name: "Ensure that Storage Account access is restricted using network rules".to_string(),
            description: "Setting the default network rule to Deny ensures that storage account \
                access is restricted to explicitly allowed networks only."
                .to_string(),
            severity: Severity::High,
            service: "storage".to_string(),
            provider: "azure".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Azure_2.0".to_string(),
                    control_id: "3.8".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-7".to_string(),
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

            let (status, msg) = if account.network_default_action == "Deny" {
                (
                    Status::Pass,
                    format!(
                        "Storage account {} has default network access rule set to Deny",
                        account.name
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Storage account {} has default network access rule set to Allow (expected Deny)",
                        account.name
                    ),
                )
            };

            reports.push(make_report(
                "storage_account_default_network_access_rule_deny",
                "Ensure that Storage Account access is restricted using network rules",
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
