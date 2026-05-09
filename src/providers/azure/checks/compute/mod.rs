pub mod compute_vm_os_disk_encryption_enabled;
pub mod compute_vm_data_disks_encrypted;
pub mod compute_vm_managed_identity_enabled;
pub mod compute_vm_boot_diagnostics_enabled;
pub mod compute_vm_os_automatic_patching;
pub mod compute_vm_availability_zone_enabled;
pub mod compute_vm_disaster_recovery;
pub mod compute_vm_endpoint_protection;
pub mod compute_vm_network_security_group;
pub mod compute_vm_public_ip_address;

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
        service: "compute".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
