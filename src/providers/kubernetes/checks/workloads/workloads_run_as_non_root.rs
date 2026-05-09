use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::workloads::WorkloadsService;

pub struct WorkloadsRunAsNonRoot;

impl Check for WorkloadsRunAsNonRoot {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "workloads_run_as_non_root".to_string(),
            name: "Ensure containers do not run as root user".to_string(),
            description: "Containers running as root have elevated privileges that could allow \
                escape from the container. runAsNonRoot should be set to true or runAsRoot \
                should be false."
                .to_string(),
            severity: Severity::High,
            service: "workloads".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.2.6".to_string(),
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

                // PASS if runAsNonRoot == Some(true) OR runAsRoot == Some(false)
                let passes = container.run_as_non_root == Some(true)
                    || container.run_as_root == Some(false);

                if !passes {
                    reports.push(make_k8s_report(
                        "workloads_run_as_non_root",
                        "Ensure containers do not run as root user",
                        Severity::High,
                        Status::Fail,
                        &resource_id,
                        &resource_arn,
                        &pod.namespace,
                        &svc.cluster_name,
                        &format!(
                            "Container {}/{}/{} does not enforce non-root execution \
                             (runAsNonRoot not true, runAsRoot not false)",
                            pod.namespace, pod.name, container.name
                        ),
                        "workloads",
                        self.metadata().compliance.clone(),
                    ));
                } else {
                    reports.push(make_k8s_report(
                        "workloads_run_as_non_root",
                        "Ensure containers do not run as root user",
                        Severity::High,
                        Status::Pass,
                        &resource_id,
                        &resource_arn,
                        &pod.namespace,
                        &svc.cluster_name,
                        &format!(
                            "Container {}/{}/{} enforces non-root execution",
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
                "workloads_run_as_non_root",
                "Ensure containers do not run as root user",
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
