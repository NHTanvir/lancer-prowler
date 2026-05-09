use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::gcp::checks::compute::make_report;
use crate::providers::gcp::services::compute::GcpComputeService;

pub struct ComputeFirewallRuleNoIngress0000022;

/// Returns true if the firewall port rule allows port 22 (or all ports).
fn allows_port_22(rule: &crate::providers::gcp::services::compute::FirewallPortRule) -> bool {
    // "all" protocol means all traffic including port 22
    if rule.ip_protocol == "all" {
        return true;
    }
    if rule.ip_protocol != "tcp" {
        return false;
    }
    // Empty ports list means all ports for this protocol
    if rule.ports.is_empty() {
        return true;
    }
    for port_spec in &rule.ports {
        // Port can be "22" or a range like "0-1024"
        if port_spec == "22" {
            return true;
        }
        if let Some((start, end)) = port_spec.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u16>(), end.parse::<u16>()) {
                if s <= 22 && 22 <= e {
                    return true;
                }
            }
        }
    }
    false
}

impl Check for ComputeFirewallRuleNoIngress0000022 {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "compute_firewall_rule_no_ingress_0_0_0_0_22".to_string(),
            name: "Ensure that SSH access from the internet (0.0.0.0/0) is not allowed via firewall rules".to_string(),
            description: "Firewall rules that allow ingress from 0.0.0.0/0 (the internet) \
                on port 22 (SSH) expose instances to brute-force and exploitation attacks. \
                Restrict SSH access to specific trusted IP ranges or use Identity-Aware Proxy."
                .to_string(),
            severity: Severity::Critical,
            service: "compute".to_string(),
            provider: "gcp".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_GCP_1.3".to_string(),
                    control_id: "3.6".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-7".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<GcpComputeService>() {
            Some(s) => s,
            None => return vec![],
        };

        let mut reports = Vec::new();

        for rule in &svc.firewall_rules {
            if rule.direction != "INGRESS" || rule.disabled {
                continue;
            }
            if !rule.source_ranges.iter().any(|r| r == "0.0.0.0/0") {
                continue;
            }
            if rule.allowed_ports.iter().any(allows_port_22) {
                let resource_arn = format!(
                    "//compute.googleapis.com/projects/{}/global/firewalls/{}",
                    svc.project_id, rule.name
                );
                reports.push(make_report(
                    "compute_firewall_rule_no_ingress_0_0_0_0_22",
                    "Ensure that SSH access from the internet (0.0.0.0/0) is not allowed via firewall rules",
                    Severity::Critical,
                    Status::Fail,
                    &rule.name,
                    &resource_arn,
                    "global",
                    &svc.project_id,
                    &format!(
                        "Firewall rule {} allows SSH (port 22) ingress from 0.0.0.0/0",
                        rule.name
                    ),
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_report(
                "compute_firewall_rule_no_ingress_0_0_0_0_22",
                "Ensure that SSH access from the internet (0.0.0.0/0) is not allowed via firewall rules",
                Severity::Critical,
                Status::Pass,
                &svc.project_id,
                &format!("//compute.googleapis.com/projects/{}/global/firewalls", svc.project_id),
                "global",
                &svc.project_id,
                "No firewall rules allow SSH (port 22) ingress from 0.0.0.0/0",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
