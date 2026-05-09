use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::workloads::WorkloadsService;

pub struct WorkloadsNoRootCapabilities;

const DANGEROUS_CAPABILITIES: &[&str] = &[
    "SYS_ADMIN",
    "NET_ADMIN",
    "ALL",
    "CAP_SYS_ADMIN",
];

impl Check for WorkloadsNoRootCapabilities {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "workloads_no_root_capabilities".to_string(),
            name: "Ensure containers do not add dangerous Linux capabilities".to_string(),
            description: "Capabilities such as SYS_ADMIN, NET_ADMIN, and ALL grant elevated \
                kernel-level privileges that can be used to escape container isolation or \
                compromise the host."
                .to_string(),
            severity: Severity::High,
            service: "workloads".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.2.7".to_string(),
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

                let dangerous: Vec<&str> = container
                    .capabilities_add
                    .iter()
                    .filter(|cap| DANGEROUS_CAPABILITIES.contains(&cap.as_str()))
                    .map(|cap| cap.as_str())
                    .collect();

                if !dangerous.is_empty() {
                    reports.push(make_k8s_report(
                        "workloads_no_root_capabilities",
                        "Ensure containers do not add dangerous Linux capabilities",
                        Severity::High,
                        Status::Fail,
                        &resource_id,
                        &resource_arn,
                        &pod.namespace,
                        &svc.cluster_name,
                        &format!(
                            "Container {}/{}/{} adds dangerous capabilities: {}",
                            pod.namespace,
                            pod.name,
                            container.name,
                            dangerous.join(", ")
                        ),
                        "workloads",
                        self.metadata().compliance.clone(),
                    ));
                } else {
                    reports.push(make_k8s_report(
                        "workloads_no_root_capabilities",
                        "Ensure containers do not add dangerous Linux capabilities",
                        Severity::High,
                        Status::Pass,
                        &resource_id,
                        &resource_arn,
                        &pod.namespace,
                        &svc.cluster_name,
                        &format!(
                            "Container {}/{}/{} does not add dangerous capabilities",
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
                "workloads_no_root_capabilities",
                "Ensure containers do not add dangerous Linux capabilities",
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
