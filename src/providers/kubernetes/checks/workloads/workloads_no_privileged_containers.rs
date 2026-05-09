use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::workloads::WorkloadsService;

pub struct WorkloadsNoPrivilegedContainers;

impl Check for WorkloadsNoPrivilegedContainers {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "workloads_no_privileged_containers".to_string(),
            name: "Ensure containers do not run in privileged mode".to_string(),
            description: "Privileged containers have unrestricted access to host resources and \
                can bypass most Kubernetes security controls. Containers should not run with \
                privileged: true."
                .to_string(),
            severity: Severity::Critical,
            service: "workloads".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.2.1".to_string(),
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

                if container.privileged {
                    reports.push(make_k8s_report(
                        "workloads_no_privileged_containers",
                        "Ensure containers do not run in privileged mode",
                        Severity::Critical,
                        Status::Fail,
                        &resource_id,
                        &resource_arn,
                        &pod.namespace,
                        &svc.cluster_name,
                        &format!(
                            "Container {}/{}/{} is running in privileged mode",
                            pod.namespace, pod.name, container.name
                        ),
                        "workloads",
                        self.metadata().compliance.clone(),
                    ));
                } else {
                    reports.push(make_k8s_report(
                        "workloads_no_privileged_containers",
                        "Ensure containers do not run in privileged mode",
                        Severity::Critical,
                        Status::Pass,
                        &resource_id,
                        &resource_arn,
                        &pod.namespace,
                        &svc.cluster_name,
                        &format!(
                            "Container {}/{}/{} is not running in privileged mode",
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
                "workloads_no_privileged_containers",
                "Ensure containers do not run in privileged mode",
                Severity::Critical,
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
