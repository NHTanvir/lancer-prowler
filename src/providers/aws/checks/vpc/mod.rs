pub mod vpc_different_regions;
pub mod vpc_endpoint_connections_trust_boundaries;
pub mod vpc_flow_logs_enabled;
pub mod vpc_peering_routing_tables_with_least_privilege;
pub mod vpc_subnet_no_public_ip_by_default;

use crate::models::{CheckReport, ComplianceRef, Severity, Status};
use chrono::Utc;

/// Build a CheckReport for a VPC check.
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
        service: "vpc".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
