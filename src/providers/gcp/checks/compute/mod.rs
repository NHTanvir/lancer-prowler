pub mod compute_instance_ip_forwarding_disabled;
pub mod compute_instance_serial_port_disabled;
pub mod compute_instance_oslogin_enabled;
pub mod compute_instance_shielded_vm_enabled;
pub mod compute_instance_no_public_ip;
pub mod compute_instance_default_service_account;
pub mod compute_instance_default_service_account_full_access;
pub mod compute_firewall_rule_no_ingress_0_0_0_0_22;
pub mod compute_firewall_rule_no_ingress_0_0_0_0_3389;

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
        service: "compute".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
