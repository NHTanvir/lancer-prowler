use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::kubernetes::checks::make_k8s_report;
use crate::providers::kubernetes::services::workloads::WorkloadsService;

pub struct WorkloadsAutomountServiceAccountToken;

impl Check for WorkloadsAutomountServiceAccountToken {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "workloads_automount_service_account_token".to_string(),
            name: "Ensure automounting of service account tokens is disabled".to_string(),
            description: "By default, Kubernetes automatically mounts the service account token \
                into each pod. Pods that do not need to communicate with the API server should \
                explicitly disable this with automountServiceAccountToken: false."
                .to_string(),
            severity: Severity::Medium,
            service: "workloads".to_string(),
            provider: "kubernetes".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_Kubernetes_1.8".to_string(),
                    control_id: "5.1.6".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "IA-5".to_string(),
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

            // FAIL if automount_service_account_token != Some(false)
            if pod.automount_service_account_token != Some(false) {
                reports.push(make_k8s_report(
                    "workloads_automount_service_account_token",
                    "Ensure automounting of service account tokens is disabled",
                    Severity::Medium,
                    Status::Fail,
                    &resource_id,
                    &resource_arn,
                    &pod.namespace,
                    &svc.cluster_name,
                    &format!(
                        "Pod {}/{} does not explicitly disable automountServiceAccountToken",
                        pod.namespace, pod.name
                    ),
                    "workloads",
                    self.metadata().compliance.clone(),
                ));
            } else {
                reports.push(make_k8s_report(
                    "workloads_automount_service_account_token",
                    "Ensure automounting of service account tokens is disabled",
                    Severity::Medium,
                    Status::Pass,
                    &resource_id,
                    &resource_arn,
                    &pod.namespace,
                    &svc.cluster_name,
                    &format!(
                        "Pod {}/{} has automountServiceAccountToken=false",
                        pod.namespace, pod.name
                    ),
                    "workloads",
                    self.metadata().compliance.clone(),
                ));
            }
        }

        if reports.is_empty() {
            reports.push(make_k8s_report(
                "workloads_automount_service_account_token",
                "Ensure automounting of service account tokens is disabled",
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
