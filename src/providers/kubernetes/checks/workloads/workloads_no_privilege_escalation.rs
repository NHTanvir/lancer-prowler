use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::workloads::WorkloadsService;

pub struct WorkloadsNoPrivilegeEscalation;

impl Check for WorkloadsNoPrivilegeEscalation {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "workloads_no_privilege_escalation".to_string(),
            name: "Ensure containers do not allow privilege escalation".to_string(),
            description: "Containers with allowPrivilegeEscalation set to true (or unset) can \
                gain more privileges than their parent process. This should be explicitly \
                set to false."
                .to_string(),
            severity: Severity::High,
            service: "workloads".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.2.5".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "CM-7".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<WorkloadsService>() {
            Some(s) => s,
            None => return vec![],
        };

        let mut reports = Vec::new();

        for pod in &svc.pods {
            for container in &pod.containers {
                let resource_id = format!("{}/{}/{}", pod.namespace, pod.name, container.name);
                let resource_arn = format!(
                    "kubernetes://namespaces/{}/pods/{}/containers/{}",
                    pod.namespace, pod.name, container.name
                );

                // FAIL if allow_privilege_escalation is Some(true) or None (unset)
                let fails = container.allow_privilege_escalation != Some(false);

                if fails {
                    reports.push(make_k8s_report(
                        "workloads_no_privilege_escalation",
                        "Ensure containers do not allow privilege escalation",
                        Severity::High,
                        Status::Fail,
                        &resource_id,
                        &resource_arn,
                        &pod.namespace,
                        &svc.cluster_name,
                        &format!(
                            "Container {}/{}/{} does not explicitly set allowPrivilegeEscalation=false",
                            pod.namespace, pod.name, container.name
                        ),
                        "workloads",
                        self.metadata().compliance.clone(),
                    ));
                } else {
                    reports.push(make_k8s_report(
                        "workloads_no_privilege_escalation",
                        "Ensure containers do not allow privilege escalation",
                        Severity::High,
                        Status::Pass,
                        &resource_id,
                        &resource_arn,
                        &pod.namespace,
                        &svc.cluster_name,
                        &format!(
                            "Container {}/{}/{} has allowPrivilegeEscalation=false",
                            pod.namespace, pod.name, container.name
                        ),
                        "workloads",
                        self.metadata().compliance.clone(),
                    ));
                }
            }
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "workloads_no_privilege_escalation",
                "Ensure containers do not allow privilege escalation",
                Severity::High,
                Status::Pass,
                &svc.cluster_name,
                &format!("kubernetes://clusters/{}", svc.cluster_name),
                "cluster",
                &svc.cluster_name,
                "No pods found (stub mode — no data)",
                "workloads",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
