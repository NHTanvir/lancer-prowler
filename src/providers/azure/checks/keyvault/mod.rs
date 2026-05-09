pub mod keyvault_soft_delete_enabled;
pub mod keyvault_purge_protection_enabled;
pub mod keyvault_public_network_access_disabled;
pub mod keyvault_rbac_authorization_enabled;
pub mod keyvault_default_network_access_rule_deny;
pub mod keyvault_premium_sku;
pub mod keyvault_recoverable;
pub mod keyvault_logging_enabled;
pub mod keyvault_private_endpoint;
pub mod keyvault_key_expiration_set;

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
        service: "keyvault".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
