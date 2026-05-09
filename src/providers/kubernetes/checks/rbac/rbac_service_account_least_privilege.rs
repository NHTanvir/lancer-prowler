use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::rbac::RbacService;

pub struct RbacServiceAccountLeastPrivilege;

impl Check for RbacServiceAccountLeastPrivilege {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rbac_service_account_least_privilege".to_string(),
            name: "Ensure ServiceAccounts are not bound to cluster-admin role".to_string(),
            description: "ServiceAccounts bound to cluster-admin have unrestricted cluster access. \
                Applications should use the minimum permissions required to function."
                .to_string(),
            severity: Severity::Medium,
            service: "rbac".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.1.6".to_string(),
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

            let sa_subjects: Vec<&str> = binding
                .subjects
                .iter()
                .filter(|s| s.kind == "ServiceAccount")
                .map(|s| s.name.as_str())
                .collect();

            if !sa_subjects.is_empty() {
                let resource_arn = format!(
                    "kubernetes://clusterrolebindings/{}",
                    binding.name
                );
                reports.push(make_k8s_report(
                    "rbac_service_account_least_privilege",
                    "Ensure ServiceAccounts are not bound to cluster-admin role",
                    Severity::Medium,
                    Status::Fail,
                    &binding.name,
                    &resource_arn,
                    "cluster",
                    &svc.cluster_name,
                    &format!(
                        "ClusterRoleBinding {} binds cluster-admin to ServiceAccount(s): {}",
                        binding.name,
                        sa_subjects.join(", ")
                    ),
                    "rbac",
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "rbac_service_account_least_privilege",
                "Ensure ServiceAccounts are not bound to cluster-admin role",
                Severity::Medium,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No ServiceAccounts are bound to cluster-admin role",
                "rbac",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
