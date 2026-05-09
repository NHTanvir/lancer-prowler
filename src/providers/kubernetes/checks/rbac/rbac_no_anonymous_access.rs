use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::rbac::RbacService;

pub struct RbacNoAnonymousAccess;

impl Check for RbacNoAnonymousAccess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rbac_no_anonymous_access".to_string(),
            name: "Ensure anonymous requests are not granted RBAC permissions".to_string(),
            description: "ClusterRoleBindings must not include system:anonymous or \
                system:unauthenticated as subjects, which would grant permissions to \
                unauthenticated callers."
                .to_string(),
            severity: Severity::Critical,
            service: "rbac".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.1.2".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "IA-2".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<RbacService>() {
            Some(s) => s,
            None => return vec![],
        };

        const ANONYMOUS: &[&str] = &["system:anonymous", "system:unauthenticated"];
        let mut reports = Vec::new();

        for binding in &svc.cluster_role_bindings {
            let anon_subjects: Vec<&str> = binding
                .subjects
                .iter()
                .filter(|s| ANONYMOUS.contains(&s.name.as_str()))
                .map(|s| s.name.as_str())
                .collect();

            let resource_arn = format!(
                "kubernetes://clusterrolebindings/{}",
                binding.name
            );

            if !anon_subjects.is_empty() {
                reports.push(make_k8s_report(
                    "rbac_no_anonymous_access",
                    "Ensure anonymous requests are not granted RBAC permissions",
                    Severity::Critical,
                    Status::Fail,
                    &binding.name,
                    &resource_arn,
                    "cluster",
                    &svc.cluster_name,
                    &format!(
                        "ClusterRoleBinding {} grants permissions to anonymous subjects: {}",
                        binding.name,
                        anon_subjects.join(", ")
                    ),
                    "rbac",
                    self.metadata().compliance.clone(),
                ));
            } else {
                reports.push(make_k8s_report(
                    "rbac_no_anonymous_access",
                    "Ensure anonymous requests are not granted RBAC permissions",
                    Severity::Critical,
                    Status::Pass,
                    &binding.name,
                    &resource_arn,
                    "cluster",
                    &svc.cluster_name,
                    &format!(
                        "ClusterRoleBinding {} does not include anonymous subjects",
                        binding.name
                    ),
                    "rbac",
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "rbac_no_anonymous_access",
                "Ensure anonymous requests are not granted RBAC permissions",
                Severity::Critical,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No ClusterRoleBindings found (no anonymous access possible)",
                "rbac",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
