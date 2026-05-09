pub mod storage_account_secure_transfer_required;
pub mod storage_account_minimum_tls_version_1_2;
pub mod storage_account_public_access_level_is_private;
pub mod storage_account_default_network_access_rule_deny;
pub mod storage_account_customer_managed_key;
pub mod storage_account_infrastructure_encryption_enabled;
pub mod storage_account_blob_soft_delete_enabled;
pub mod storage_account_container_soft_delete_enabled;
pub mod storage_account_versioning_enabled;
pub mod storage_account_shared_key_access_disabled;

use crate::models::{CheckReport, ComplianceRef, Severity, Status};
use chrono::Utc;

#[allow(clippy::too_many_arguments)]
pub fn make_report(
    check_id: &str,
    check_name: &str,
    severity: Severity,
    status: Status,
    resource_id: &str,
    resource_arn: &str,
    region: &str,
    account_id: &str,
    status_extended: &str,
    compliance: Vec<ComplianceRef>,
) -> CheckReport {
    CheckReport {
        check_id: check_id.to_string(),
        check_name: check_name.to_string(),
        status,
        status_extended: status_extended.to_string(),
        severity,
        resource_id: resource_id.to_string(),
        resource_arn: resource_arn.to_string(),
        region: region.to_string(),
        provider: "azure".to_string(),
        service: "storage".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
