pub mod iam_no_service_account_with_admin_privileges;
pub mod iam_service_account_key_not_user_managed;
pub mod iam_avoid_primitive_roles;
pub mod iam_project_has_owner;
pub mod iam_no_public_access;
pub mod iam_sa_no_admin_privileges;
pub mod iam_service_account_key_rotation_90_days;
pub mod iam_workload_identity_federation_enabled;

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
        service: "iam".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
