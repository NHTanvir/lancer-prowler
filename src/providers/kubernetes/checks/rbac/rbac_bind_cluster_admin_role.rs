use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::rbac::RbacService;

pub struct RbacBindClusterAdminRole;

impl Check for RbacBindClusterAdminRole {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rbac_bind_cluster_admin_role".to_string(),
            name: "Ensure cluster-admin-equivalent ClusterRoles are not referenced by bindings"
                .to_string(),
            description: "ClusterRoles that are equivalent to cluster-admin (wildcard resource/verb \
                access) should not be referenced by ClusterRoleBindings as they grant full cluster \
                access."
                .to_string(),
            severity: Severity::High,
            service: "rbac".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.1.1".to_string(),
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

        // Collect names of cluster-admin-equivalent roles
        let admin_equiv_roles: Vec<&str> = svc
            .cluster_roles
            .iter()
            .filter(|r| r.is_cluster_admin_equivalent)
            .map(|r| r.name.as_str())
            .collect();

        for role_name in &admin_equiv_roles {
            let bindings_referencing: Vec<&str> = svc
                .cluster_role_bindings
                .iter()
                .filter(|b| b.role_ref_name.as_str() == *role_name)
                .map(|b| b.name.as_str())
                .collect();

            let resource_arn = format!("kubernetes://clusterroles/{}", role_name);

            if !bindings_referencing.is_empty() {
                reports.push(make_k8s_report(
                    "rbac_bind_cluster_admin_role",
                    "Ensure cluster-admin-equivalent ClusterRoles are not referenced by bindings",
                    Severity::High,
                    Status::Fail,
                    role_name,
                    &resource_arn,
                    "cluster",
                    &svc.cluster_name,
                    &format!(
                        "Cluster-admin-equivalent ClusterRole {} is referenced by bindings: {}",
                        role_name,
                        bindings_referencing.join(", ")
                    ),
                    "rbac",
                    self.metadata().compliance.clone(),
                ));
            } else {
                reports.push(make_k8s_report(
                    "rbac_bind_cluster_admin_role",
                    "Ensure cluster-admin-equivalent ClusterRoles are not referenced by bindings",
                    Severity::High,
                    Status::Pass,
                    role_name,
                    &resource_arn,
                    "cluster",
                    &svc.cluster_name,
                    &format!(
                        "Cluster-admin-equivalent ClusterRole {} has no active ClusterRoleBindings",
                        role_name
                    ),
                    "rbac",
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "rbac_bind_cluster_admin_role",
                "Ensure cluster-admin-equivalent ClusterRoles are not referenced by bindings",
                Severity::High,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No cluster-admin-equivalent ClusterRoles found",
                "rbac",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
