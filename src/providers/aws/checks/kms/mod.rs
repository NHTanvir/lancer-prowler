pub mod kms_cmk_not_pending_deletion;
pub mod kms_cmk_rotation_enabled;
pub mod kms_key_not_disabled;

use crate::models::{CheckReport, ComplianceRef, Severity, Status};
use chrono::Utc;

/// Build a CheckReport for a KMS check.
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
        provider: "aws".to_string(),
        service: "kms".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
