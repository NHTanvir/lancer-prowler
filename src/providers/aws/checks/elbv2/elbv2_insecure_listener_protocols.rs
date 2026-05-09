use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::elbv2::make_report;
use crate::providers::aws::services::elbv2::Elbv2Service;

pub struct Elbv2InsecureListenerProtocols;

impl Check for Elbv2InsecureListenerProtocols {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "elbv2_insecure_listener_protocols".to_string(),
            name: "Ensure internet-facing ELBv2 listeners do not use HTTP".to_string(),
            description: "HTTP traffic is unencrypted and can be intercepted. \
                Internet-facing load balancers should use HTTPS to protect data \
                in transit between clients and the load balancer."
                .to_string(),
            severity: Severity::High,
            service: "elbv2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_1.4".to_string(),
                    control_id: "2.1.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-8".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<Elbv2Service>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for lb in &svc.load_balancers {
            if lb.scheme != "internet-facing" {
                // Only check internet-facing LBs for insecure HTTP listeners
                continue;
            }

            for listener in &lb.listeners {
                if listener.protocol == "HTTP" {
                    reports.push(make_report(
                        "elbv2_insecure_listener_protocols",
                        "Ensure internet-facing ELBv2 listeners do not use HTTP",
                        Severity::High,
                        Status::Fail,
                        &lb.name,
                        &listener.arn,
                        &lb.region,
                        account_id,
                        &format!(
                            "Internet-facing load balancer {} has an HTTP listener on port {} (unencrypted)",
                            lb.name, listener.port
                        ),
                        self.metadata().compliance.clone(),
                    ));
                } else {
                    reports.push(make_report(
                        "elbv2_insecure_listener_protocols",
                        "Ensure internet-facing ELBv2 listeners do not use HTTP",
                        Severity::High,
                        Status::Pass,
                        &lb.name,
                        &listener.arn,
                        &lb.region,
                        account_id,
                        &format!(
                            "Load balancer {} listener on port {} uses {} (encrypted)",
                            lb.name, listener.port, listener.protocol
                        ),
                        self.metadata().compliance.clone(),
                    ));
                }
            }
        }

        reports
    }
}
