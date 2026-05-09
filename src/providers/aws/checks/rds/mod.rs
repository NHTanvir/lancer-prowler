pub mod rds_instance_backup_enabled;
pub mod rds_instance_default_admin;
pub mod rds_instance_encrypted;
pub mod rds_instance_minor_version_upgrade_enabled;
pub mod rds_instance_multi_az;
pub mod rds_instance_public_access;
pub mod rds_instance_storage_encrypted;
pub mod rds_snapshots_encrypted;
pub mod rds_snapshots_public_access;

use crate::models::{CheckReport, ComplianceRef, Severity, Status};
use chrono::Utc;

/// Build a CheckReport for an RDS check.
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
        service: "rds".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
