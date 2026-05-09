//! VMware / Broadcom VMware Cloud Foundation (VCF) provider (stub).

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct VmwareProvider {
    pub sddc_id: String,
}

impl VmwareProvider {
    pub fn new_stub(sddc_id: String) -> Self {
        Self { sddc_id }
    }
}

impl Provider for VmwareProvider {
    fn name(&self) -> &str { "VMware / Broadcom VCF" }
    fn provider_id(&self) -> &str { "vmware" }
    fn account_id(&self) -> &str { &self.sddc_id }
    fn regions(&self) -> Vec<String> { vec!["on-prem".into()] }
}

pub const SERVICES: &[&str] = &["vsphere", "nsx", "vsan", "aria", "tanzu"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("vsphere_esxi_lockdown_mode", "vsphere", Severity::High),
        meta("vsphere_vm_encryption_enabled", "vsphere", Severity::High),
        meta("nsx_firewall_default_deny", "nsx", Severity::High),
        meta("vsan_encryption_at_rest", "vsan", Severity::High),
        meta("aria_audit_logs_enabled", "aria", Severity::Medium),
        meta("tanzu_no_privileged_pods", "tanzu", Severity::High),
    ]
}

pub fn run_stub_scan(p: &VmwareProvider) -> Vec<CheckReport> {
    sample_checks().into_iter().map(|m| stub_report(p, m)).collect()
}

fn stub_report(p: &VmwareProvider, m: CheckMetadata) -> CheckReport {
    CheckReport {
        check_id: m.id.clone(),
        check_name: m.name.clone(),
        status: Status::Unknown,
        status_extended: "stub: real VMware integration uses the vSphere / NSX REST APIs".into(),
        severity: m.severity,
        resource_id: p.sddc_id.clone(),
        resource_arn: format!("vmware://{}", p.sddc_id),
        region: "on-prem".into(),
        provider: "vmware".into(),
        service: m.service,
        account_id: p.sddc_id.clone(),
        compliance: m.compliance,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

fn meta(id: &str, service: &str, sev: Severity) -> CheckMetadata {
    CheckMetadata {
        id: id.into(),
        name: id.replace('_', " "),
        description: id.replace('_', " "),
        severity: sev,
        service: service.into(),
        provider: "vmware".into(),
        compliance: vec![ComplianceRef {
            framework: "cis_vmware".into(),
            control_id: "tbd".into(),
        }],
    }
}
