use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::network::NetworkService;

pub struct NetworkDefaultDenyPolicy;

impl Check for NetworkDefaultDenyPolicy {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "network_default_deny_policy".to_string(),
            name: "Ensure a default-deny NetworkPolicy exists for all ingress and egress".to_string(),
            description: "A default-deny NetworkPolicy (empty pod selector covering all pods) \
                that blocks all ingress and egress is a security best practice. Traffic \
                should be explicitly allowed rather than implicitly permitted."
                .to_string(),
            severity: Severity::High,
            service: "network".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.3.2".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-7".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<NetworkService>() {
            Some(s) => s,
            None => return vec![],
        };

        // Collect all unique namespaces from policies
        let mut namespaces_with_default_deny: Vec<&str> = svc
            .network_policies
            .iter()
            .filter(|p| {
                p.pod_selector_empty
                    && p.ingress_rules.is_empty()
                    && p.egress_rules.is_empty()
            })
            .map(|p| p.namespace.as_str())
            .collect();

        namespaces_with_default_deny.sort_unstable();
        namespaces_with_default_deny.dedup();

        if svc.network_policies.is_empty() {
            // Stub mode — emit a single PASS with note
            return vec![make_k8s_report(
                "network_default_deny_policy",
                "Ensure a default-deny NetworkPolicy exists for all ingress and egress",
                Severity::High,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No NetworkPolicies found — stub mode, skipping default-deny check",
                "network",
                self.metadata().compliance.clone(),
            )];
        }

        let mut reports = Vec::new();

        // Collect all unique namespaces present in policies
        let mut all_namespaces: Vec<&str> = svc
            .network_policies
            .iter()
            .map(|p| p.namespace.as_str())
            .collect();
        all_namespaces.sort_unstable();
        all_namespaces.dedup();

        for ns in &all_namespaces {
            let has_default_deny = namespaces_with_default_deny.contains(ns);
            let resource_arn = format!("kubernetes://namespaces/{}", ns);

            if has_default_deny {
                reports.push(make_k8s_report(
                    "network_default_deny_policy",
                    "Ensure a default-deny NetworkPolicy exists for all ingress and egress",
                    Severity::High,
                    Status::Pass,
                    ns,
                    &resource_arn,
                    ns,
                    &svc.cluster_name,
                    &format!("Namespace {} has a default-deny NetworkPolicy", ns),
                    "network",
                    self.metadata().compliance.clone(),
                ));
            } else {
                reports.push(make_k8s_report(
                    "network_default_deny_policy",
                    "Ensure a default-deny NetworkPolicy exists for all ingress and egress",
                    Severity::High,
                    Status::Fail,
                    ns,
                    &resource_arn,
                    ns,
                    &svc.cluster_name,
                    &format!(
                        "Namespace {} does not have a default-deny NetworkPolicy \
                         (empty podSelector with no ingress/egress rules)",
                        ns
                    ),
                    "network",
                    self.metadata().compliance.clone(),
                ));
            }
        }

        reports
    }
}
