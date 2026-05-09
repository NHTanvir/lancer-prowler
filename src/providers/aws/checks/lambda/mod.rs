pub mod lambda_function_environment_variables_encrypted;
pub mod lambda_function_in_vpc;
pub mod lambda_function_not_publicly_accessible;
pub mod lambda_function_url_public;

use crate::models::{CheckReport, ComplianceRef, Severity, Status};
use chrono::Utc;

/// Build a CheckReport for a Lambda check.
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
        service: "lambda".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
