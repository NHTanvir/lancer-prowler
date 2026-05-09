use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::workloads::WorkloadsService;

pub struct WorkloadsResourceLimitsSet;

impl Check for WorkloadsResourceLimitsSet {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "workloads_resource_limits_set".to_string(),
            name: "Ensure containers have CPU and memory resource limits set".to_string(),
            description: "Containers without resource limits can consume all node resources, \
                causing denial of service for other workloads. Resource limits should always \
                be defined."
                .to_string(),
            severity: Severity::Medium,
            service: "workloads".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.2.4".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-6".to_string(),
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

                if !container.resource_limits_set {
                    reports.push(make_k8s_report(
                        "workloads_resource_limits_set",
                        "Ensure containers have CPU and memory resource limits set",
                        Severity::Medium,
                        Status::Fail,
                        &resource_id,
                        &resource_arn,
                        &pod.namespace,
                        &svc.cluster_name,
                        &format!(
                            "Container {}/{}/{} does not have resource limits set",
                            pod.namespace, pod.name, container.name
                        ),
                        "workloads",
                        self.metadata().compliance.clone(),
                    ));
                } else {
                    reports.push(make_k8s_report(
                        "workloads_resource_limits_set",
                        "Ensure containers have CPU and memory resource limits set",
                        Severity::Medium,
                        Status::Pass,
                        &resource_id,
                        &resource_arn,
                        &pod.namespace,
                        &svc.cluster_name,
                        &format!(
                            "Container {}/{}/{} has resource limits set",
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
                "workloads_resource_limits_set",
                "Ensure containers have CPU and memory resource limits set",
                Severity::Medium,
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
