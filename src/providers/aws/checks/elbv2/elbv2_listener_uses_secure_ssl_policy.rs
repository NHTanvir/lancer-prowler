use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::elbv2::make_report;
use crate::providers::aws::services::elbv2::Elbv2Service;

pub struct Elbv2ListenerUsesSecureSslPolicy;

/// Deprecated/insecure SSL policies that should not be used.
const INSECURE_SSL_POLICIES: &[&str] = &[
    "ELBSecurityPolicy-2016-08",
    "ELBSecurityPolicy-TLS-1-0-2015-04",
];

impl Check for Elbv2ListenerUsesSecureSslPolicy {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "elbv2_listener_uses_secure_ssl_policy".to_string(),
            name: "Ensure ELBv2 HTTPS listeners use a secure SSL policy".to_string(),
            description: "Deprecated SSL policies support older TLS versions and ciphers \
                that are vulnerable to known attacks. HTTPS listeners should use a current \
                security policy that enforces TLS 1.2 or higher."
                .to_string(),
            severity: Severity::Medium,
            service: "elbv2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_1.4".to_string(),
                    control_id: "2.1.2".to_string(),
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
            for listener in &lb.listeners {
                // Only check HTTPS listeners
                if listener.protocol != "HTTPS" && listener.protocol != "TLS" {
                    continue;
                }

                let (status, msg) = match &listener.ssl_policy {
                    None => (
                        Status::Pass,
                        format!(
                            "Load balancer {} listener on port {} has no explicit SSL policy",
                            lb.name, listener.port
                        ),
                    ),
                    Some(policy) => {
                        if INSECURE_SSL_POLICIES.contains(&policy.as_str()) {
                            (
                                Status::Fail,
                                format!(
                                    "Load balancer {} listener on port {} uses deprecated SSL policy: {}",
                                    lb.name, listener.port, policy
                                ),
                            )
                        } else {
                            (
                                Status::Pass,
                                format!(
                                    "Load balancer {} listener on port {} uses SSL policy: {}",
                                    lb.name, listener.port, policy
                                ),
                            )
                        }
                    }
                };

                reports.push(make_report(
                    "elbv2_listener_uses_secure_ssl_policy",
                    "Ensure ELBv2 HTTPS listeners use a secure SSL policy",
                    Severity::Medium,
                    status,
                    &lb.name,
                    &listener.arn,
                    &lb.region,
                    account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                ));
            }
        }

        reports
    }
}
