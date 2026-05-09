pub mod storage_bucket_uniform_bucket_level_access;
pub mod storage_bucket_public_access_prevention;
pub mod storage_bucket_versioning_enabled;
pub mod storage_bucket_logging_enabled;
pub mod storage_bucket_kms_encryption;
pub mod storage_bucket_retention_policy;
pub mod storage_bucket_not_publicly_accessible;
pub mod storage_bucket_label_environment;

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
        provider: "gcp".to_string(),
        service: "storage".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
