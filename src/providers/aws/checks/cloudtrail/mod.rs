pub mod cloudtrail_cloudwatch_logging_enabled;
pub mod cloudtrail_kms_encryption_enabled;
pub mod cloudtrail_log_file_validation_enabled;
pub mod cloudtrail_logs_s3_bucket_is_not_publicly_accessible;
pub mod cloudtrail_multi_region_enabled;
pub mod cloudtrail_s3_dataevents_read_enabled;
pub mod cloudtrail_s3_dataevents_write_enabled;
pub mod cloudtrail_threat_detection_enumeration;
pub mod cloudtrail_threat_detection_privilege_escalation;

use crate::models::{CheckReport, ComplianceRef, Severity, Status};
use chrono::Utc;

/// Build a CheckReport for a CloudTrail check.
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
        service: "cloudtrail".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
