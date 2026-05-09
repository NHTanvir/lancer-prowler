//! OpenStack provider (stub).

use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::provider::Provider;

pub struct OpenStackProvider {
    pub project_id: String,
}

impl OpenStackProvider {
    pub fn new_stub(project_id: String) -> Self {
        Self { project_id }
    }
}

impl Provider for OpenStackProvider {
    fn name(&self) -> &str { "OpenStack" }
    fn provider_id(&self) -> &str { "openstack" }
    fn account_id(&self) -> &str { &self.project_id }
    fn regions(&self) -> Vec<String> { vec!["RegionOne".to_string()] }
}

pub const SERVICES: &[&str] = &["keystone", "nova", "neutron", "swift", "cinder", "glance"];

pub fn sample_checks() -> Vec<CheckMetadata> {
    vec![
        meta("keystone_admin_no_default_password", "keystone", Severity::Critical),
        meta("nova_instance_no_floating_ip", "nova", Severity::Medium),
        meta("neutron_secgroup_no_open_ingress", "neutron", Severity::High),
        meta("swift_container_not_public_read", "swift", Severity::High),
        meta("cinder_volume_encrypted", "cinder", Severity::High),
    ]
}

pub fn run_stub_scan(p: &OpenStackProvider) -> Vec<CheckReport> {
    sample_checks().into_iter().map(|m| stub_report(p, m)).collect()
}

fn stub_report(p: &OpenStackProvider, m: CheckMetadata) -> CheckReport {
    CheckReport {
        check_id: m.id.clone(),
        check_name: m.name.clone(),
        status: Status::Unknown,
        status_extended: "stub: real OpenStack integration uses the Keystone / Nova / Neutron APIs".into(),
        severity: m.severity,
        resource_id: p.project_id.clone(),
        resource_arn: format!("openstack://{}", p.project_id),
        region: "RegionOne".into(),
        provider: "openstack".into(),
        service: m.service,
        account_id: p.project_id.clone(),
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
        provider: "openstack".into(),
        compliance: vec![ComplianceRef {
            framework: "iso27001_2022".into(),
            control_id: "A.5.15".into(),
        }],
    }
}
