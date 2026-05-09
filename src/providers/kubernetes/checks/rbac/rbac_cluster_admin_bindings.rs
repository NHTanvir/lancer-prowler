use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::rbac::RbacService;

pub struct RbacClusterAdminBindings;

impl Check for RbacClusterAdminBindings {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rbac_cluster_admin_bindings".to_string(),
            name: "Ensure cluster-admin role is not bound to non-system subjects".to_string(),
            description: "The cluster-admin role grants unrestricted access to the entire \
                cluster. Bindings to this role should be limited to system components only."
                .to_string(),
            severity: Severity::Critical,
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

        for binding in &svc.cluster_role_bindings {
            if binding.role_ref_name != "cluster-admin" {
                continue;
            }
            let non_system_subjects: Vec<&str> = binding
                .subjects
                .iter()
                .filter(|s| {
                    !s.name.starts_with("system:")
                })
                .map(|s| s.name.as_str())
                .collect();

            if !non_system_subjects.is_empty() {
                let resource_arn = format!(
                    "kubernetes://clusterrolebindings/{}",
                    binding.name
                );
                reports.push(make_k8s_report(
                    "rbac_cluster_admin_bindings",
                    "Ensure cluster-admin role is not bound to non-system subjects",
                    Severity::Critical,
                    Status::Fail,
                    &binding.name,
                    &resource_arn,
                    "cluster",
                    &svc.cluster_name,
                    &format!(
                        "ClusterRoleBinding {} binds cluster-admin to non-system subjects: {}",
                        binding.name,
                        non_system_subjects.join(", ")
                    ),
                    "rbac",
                    self.metadata().compliance.clone(),
                ));
            } else {
                let resource_arn = format!(
                    "kubernetes://clusterrolebindings/{}",
                    binding.name
                );
                reports.push(make_k8s_report(
                    "rbac_cluster_admin_bindings",
                    "Ensure cluster-admin role is not bound to non-system subjects",
                    Severity::Critical,
                    Status::Pass,
                    &binding.name,
                    &resource_arn,
                    "cluster",
                    &svc.cluster_name,
                    &format!(
                        "ClusterRoleBinding {} only binds cluster-admin to system subjects",
                        binding.name
                    ),
                    "rbac",
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "rbac_cluster_admin_bindings",
                "Ensure cluster-admin role is not bound to non-system subjects",
                Severity::Critical,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No cluster-admin ClusterRoleBindings found",
                "rbac",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
