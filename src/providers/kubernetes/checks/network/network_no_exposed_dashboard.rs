use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::network::NetworkService;

pub struct NetworkNoExposedDashboard;

impl Check for NetworkNoExposedDashboard {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "network_no_exposed_dashboard".to_string(),
            name: "Ensure the Kubernetes dashboard is not exposed via open NetworkPolicy"
                .to_string(),
            description: "The Kubernetes dashboard should not be exposed to the internet or \
                accessible without proper authentication. NetworkPolicies in the \
                kubernetes-dashboard namespace should restrict ingress."
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
                "network_no_exposed_dashboard",
                "Ensure the Kubernetes dashboard is not exposed via open NetworkPolicy",
                Severity::Medium,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No NetworkPolicies found — stub mode, no dashboard exposure detected",
                "network",
                self.metadata().compliance.clone(),
            )];
        }

        let mut reports = Vec::new();

        for policy in &svc.network_policies {
            let is_dashboard = policy.name.contains("kubernetes-dashboard")
                || policy.namespace.contains("kubernetes-dashboard");

            if !is_dashboard {
                continue;
            }

            let resource_arn = format!(
                "kubernetes://namespaces/{}/networkpolicies/{}",
                policy.namespace, policy.name
            );

            // FAIL if ingress_rules is empty (no restriction) on the dashboard namespace
            if policy.ingress_rules.is_empty() {
                reports.push(make_k8s_report(
                    "network_no_exposed_dashboard",
                    "Ensure the Kubernetes dashboard is not exposed via open NetworkPolicy",
                    Severity::Medium,
                    Status::Fail,
                    &policy.name,
                    &resource_arn,
                    &policy.namespace,
                    &svc.cluster_name,
                    &format!(
                        "NetworkPolicy {}/{} in dashboard namespace has no ingress restrictions",
                        policy.namespace, policy.name
                    ),
                    "network",
                    self.metadata().compliance.clone(),
                ));
            } else {
                reports.push(make_k8s_report(
                    "network_no_exposed_dashboard",
                    "Ensure the Kubernetes dashboard is not exposed via open NetworkPolicy",
                    Severity::Medium,
                    Status::Pass,
                    &policy.name,
                    &resource_arn,
                    &policy.namespace,
                    &svc.cluster_name,
                    &format!(
                        "NetworkPolicy {}/{} restricts dashboard ingress traffic",
                        policy.namespace, policy.name
                    ),
                    "network",
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "network_no_exposed_dashboard",
                "Ensure the Kubernetes dashboard is not exposed via open NetworkPolicy",
                Severity::Medium,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No kubernetes-dashboard NetworkPolicies found",
                "network",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
