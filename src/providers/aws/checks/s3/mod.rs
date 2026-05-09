pub mod s3_account_level_public_access_blocks;
pub mod s3_bucket_acl_prohibited;
pub mod s3_bucket_cross_account_access;
pub mod s3_bucket_default_encryption;
pub mod s3_bucket_kms_encryption;
pub mod s3_bucket_level_public_access_block;
pub mod s3_bucket_no_mfa_delete;
pub mod s3_bucket_object_lock;
pub mod s3_bucket_object_versioning;
pub mod s3_bucket_public_access;
pub mod s3_bucket_secure_transport_policy;
pub mod s3_bucket_server_access_logging_enabled;

use crate::models::{CheckReport, ComplianceRef, Severity, Status};
use chrono::Utc;

/// Build a CheckReport for an S3 check.
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
        service: "s3".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
