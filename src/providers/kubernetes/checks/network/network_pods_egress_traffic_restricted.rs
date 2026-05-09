use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::network::NetworkService;

pub struct NetworkPodsEgressTrafficRestricted;

impl Check for NetworkPodsEgressTrafficRestricted {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "network_pods_egress_traffic_restricted".to_string(),
            name: "Ensure NetworkPolicies with empty pod selectors restrict egress traffic"
                .to_string(),
            description: "NetworkPolicies that select all pods (empty podSelector) but have \
                no egress rules effectively allow all egress traffic. Policies that select \
                all pods should define explicit egress rules."
                .to_string(),
            severity: Severity::Medium,
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

        if svc.network_policies.is_empty() {
            return vec![make_k8s_report(
                "network_pods_egress_traffic_restricted",
                "Ensure NetworkPolicies with empty pod selectors restrict egress traffic",
                Severity::Medium,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No NetworkPolicies found — stub mode, no unrestricted egress detected",
                "network",
                self.metadata().compliance.clone(),
            )];
        }

        let mut reports = Vec::new();

        for policy in &svc.network_policies {
            if !policy.pod_selector_empty {
                continue;
            }

            let resource_arn = format!(
                "kubernetes://namespaces/{}/networkpolicies/{}",
                policy.namespace, policy.name
            );

            // FAIL if pod_selector_empty == true AND egress_rules is empty
            if policy.egress_rules.is_empty() {
                reports.push(make_k8s_report(
                    "network_pods_egress_traffic_restricted",
                    "Ensure NetworkPolicies with empty pod selectors restrict egress traffic",
                    Severity::Medium,
                    Status::Fail,
                    &policy.name,
                    &resource_arn,
                    &policy.namespace,
                    &svc.cluster_name,
                    &format!(
                        "NetworkPolicy {}/{} selects all pods but has no egress rules \
                         (unrestricted egress)",
                        policy.namespace, policy.name
                    ),
                    "network",
                    self.metadata().compliance.clone(),
                ));
            } else {
                reports.push(make_k8s_report(
                    "network_pods_egress_traffic_restricted",
                    "Ensure NetworkPolicies with empty pod selectors restrict egress traffic",
                    Severity::Medium,
                    Status::Pass,
                    &policy.name,
                    &resource_arn,
                    &policy.namespace,
                    &svc.cluster_name,
                    &format!(
                        "NetworkPolicy {}/{} selects all pods and has egress rules defined",
                        policy.namespace, policy.name
                    ),
                    "network",
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "network_pods_egress_traffic_restricted",
                "Ensure NetworkPolicies with empty pod selectors restrict egress traffic",
                Severity::Medium,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No NetworkPolicies with empty pod selectors found",
                "network",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
