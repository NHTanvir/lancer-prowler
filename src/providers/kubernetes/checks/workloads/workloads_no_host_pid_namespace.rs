use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::workloads::WorkloadsService;

pub struct WorkloadsNoHostPidNamespace;

impl Check for WorkloadsNoHostPidNamespace {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "workloads_no_host_pid_namespace".to_string(),
            name: "Ensure pods do not share the host process ID namespace".to_string(),
            description: "Pods that share the host PID namespace can see all processes on the \
                node and could potentially modify or kill host processes. hostPID should be \
                false."
                .to_string(),
            severity: Severity::High,
            service: "workloads".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.2.2".to_string(),
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
            let resource_id = format!("{}/{}", pod.namespace, pod.name);
            let resource_arn = format!(
                "kubernetes://namespaces/{}/pods/{}",
                pod.namespace, pod.name
            );

            if pod.host_pid {
                reports.push(make_k8s_report(
                    "workloads_no_host_pid_namespace",
                    "Ensure pods do not share the host process ID namespace",
                    Severity::High,
                    Status::Fail,
                    &resource_id,
                    &resource_arn,
                    &pod.namespace,
                    &svc.cluster_name,
                    &format!(
                        "Pod {}/{} shares the host PID namespace (hostPID=true)",
                        pod.namespace, pod.name
                    ),
                    "workloads",
                    self.metadata().compliance.clone(),
                ));
            } else {
                reports.push(make_k8s_report(
                    "workloads_no_host_pid_namespace",
                    "Ensure pods do not share the host process ID namespace",
                    Severity::High,
                    Status::Pass,
                    &resource_id,
                    &resource_arn,
                    &pod.namespace,
                    &svc.cluster_name,
                    &format!(
                        "Pod {}/{} does not share the host PID namespace",
                        pod.namespace, pod.name
                    ),
                    "workloads",
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "workloads_no_host_pid_namespace",
                "Ensure pods do not share the host process ID namespace",
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
