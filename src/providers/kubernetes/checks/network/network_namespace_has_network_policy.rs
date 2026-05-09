use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::network::NetworkService;

pub struct NetworkNamespaceHasNetworkPolicy;

impl Check for NetworkNamespaceHasNetworkPolicy {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "network_namespace_has_network_policy".to_string(),
            name: "Ensure every namespace has at least one NetworkPolicy".to_string(),
            description: "Namespaces without NetworkPolicies allow unrestricted pod-to-pod \
                communication. Every namespace should have at least one NetworkPolicy to \
                limit traffic flow."
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

        let mut reports = Vec::new();

        for namespace in &svc.namespaces_without_network_policy {
            let resource_arn = format!(
                "kubernetes://namespaces/{}",
                namespace
            );
            reports.push(make_k8s_report(
                "network_namespace_has_network_policy",
                "Ensure every namespace has at least one NetworkPolicy",
                Severity::High,
                Status::Fail,
                namespace,
                &resource_arn,
                namespace,
                &svc.cluster_name,
                &format!(
                    "Namespace {} has no NetworkPolicy — all pod traffic is unrestricted",
                    namespace
                ),
                "network",
                self.metadata().compliance.clone(),
            ));
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "network_namespace_has_network_policy",
                "Ensure every namespace has at least one NetworkPolicy",
                Severity::High,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "All namespaces have NetworkPolicies (or none detected in stub mode)",
                "network",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
