use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::rbac::RbacService;

pub struct RbacWildcardVerbs;

impl Check for RbacWildcardVerbs {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rbac_wildcard_verbs".to_string(),
            name: "Ensure ClusterRoles do not use wildcard verbs on all resources".to_string(),
            description: "ClusterRoles that allow all verbs (*) on all resources (*) grant \
                effectively full cluster access and violate the principle of least privilege."
                .to_string(),
            severity: Severity::High,
            service: "rbac".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.1.3".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-6".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<RbacService>() {
            Some(s) => s,
            None => return vec![],
        };

        let mut reports = Vec::new();

        for role in &svc.cluster_roles {
            let has_wildcard = role.rules.iter().any(|rule| {
                rule.verbs.iter().any(|v| v == "*") && rule.resources.iter().any(|r| r == "*")
            });

            let resource_arn = format!("kubernetes://clusterroles/{}", role.name);

            if has_wildcard {
                reports.push(make_k8s_report(
                    "rbac_wildcard_verbs",
                    "Ensure ClusterRoles do not use wildcard verbs on all resources",
                    Severity::High,
                    Status::Fail,
                    &role.name,
                    &resource_arn,
                    "cluster",
                    &svc.cluster_name,
                    &format!(
                        "ClusterRole {} has a rule with wildcard verbs (*) on all resources (*)",
                        role.name
                    ),
                    "rbac",
                    self.metadata().compliance.clone(),
                ));
            } else {
                reports.push(make_k8s_report(
                    "rbac_wildcard_verbs",
                    "Ensure ClusterRoles do not use wildcard verbs on all resources",
                    Severity::High,
                    Status::Pass,
                    &role.name,
                    &resource_arn,
                    "cluster",
                    &svc.cluster_name,
                    &format!(
                        "ClusterRole {} does not use wildcard verbs on all resources",
                        role.name
                    ),
                    "rbac",
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "rbac_wildcard_verbs",
                "Ensure ClusterRoles do not use wildcard verbs on all resources",
                Severity::High,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No ClusterRoles found",
                "rbac",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
