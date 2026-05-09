use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::rbac::RbacService;

pub struct RbacNoClusterAdminDefault;

impl Check for RbacNoClusterAdminDefault {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rbac_no_cluster_admin_default".to_string(),
            name: "Ensure default cluster-admin ClusterRoleBinding has no non-system subjects"
                .to_string(),
            description: "The system default cluster-admin ClusterRoleBinding should only bind \
                system components. Additional non-system subjects should not be added to it."
                .to_string(),
            severity: Severity::Medium,
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

        let resource_arn = format!(
            "kubernetes://clusterrolebindings/cluster-admin"
        );

        // Find the system default "cluster-admin" ClusterRoleBinding by name
        let default_binding = svc
            .cluster_role_bindings
            .iter()
            .find(|b| b.name == "cluster-admin");

        match default_binding {
            Some(binding) => {
                let non_system: Vec<&str> = binding
                    .subjects
                    .iter()
                    .filter(|s| !s.name.starts_with("system:"))
                    .map(|s| s.name.as_str())
                    .collect();

                if !non_system.is_empty() {
                    vec![make_k8s_report(
                        "rbac_no_cluster_admin_default",
                        "Ensure default cluster-admin ClusterRoleBinding has no non-system subjects",
                        Severity::Medium,
                        Status::Fail,
                        "cluster-admin",
                        &resource_arn,
                        "cluster",
                        &svc.cluster_name,
                        &format!(
                            "Default cluster-admin ClusterRoleBinding has non-system subjects: {}",
                            non_system.join(", ")
                        ),
                        "rbac",
                        self.metadata().compliance.clone(),
                    )]
                } else {
                    vec![make_k8s_report(
                        "rbac_no_cluster_admin_default",
                        "Ensure default cluster-admin ClusterRoleBinding has no non-system subjects",
                        Severity::Medium,
                        Status::Pass,
                        "cluster-admin",
                        &resource_arn,
                        "cluster",
                        &svc.cluster_name,
                        "Default cluster-admin ClusterRoleBinding only contains system subjects",
                        "rbac",
                        self.metadata().compliance.clone(),
                    )]
                }
            }
            None => {
                vec![make_k8s_report(
                    "rbac_no_cluster_admin_default",
                    "Ensure default cluster-admin ClusterRoleBinding has no non-system subjects",
                    Severity::Medium,
                    Status::Pass,
                    "cluster-admin",
                    &resource_arn,
                    "cluster",
                    &svc.cluster_name,
                    "No cluster-admin ClusterRoleBinding found (stub mode — no data)",
                    "rbac",
                    self.metadata().compliance.clone(),
                )]
            }
        }
    }
}
