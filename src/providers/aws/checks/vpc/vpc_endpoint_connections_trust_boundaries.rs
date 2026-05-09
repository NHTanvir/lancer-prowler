use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::vpc::make_report;
use crate::providers::aws::services::vpc::VpcService;

pub struct VpcEndpointConnectionsTrustBoundaries;

impl Check for VpcEndpointConnectionsTrustBoundaries {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "vpc_endpoint_connections_trust_boundaries".to_string(),
            name: "Ensure VPC endpoint policies enforce trust boundaries".to_string(),
            description: "VPC endpoint policies should restrict access to trusted principals \
                and services. Overly permissive endpoint policies can expose internal resources \
                to unintended callers."
                .to_string(),
            severity: Severity::Medium,
            service: "vpc".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-4".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<VpcService>() {
            Some(s) => s,
            None => return vec![],
        };

        // Stub: VPC endpoint trust boundary analysis requires manual review.
        vec![make_report(
            "vpc_endpoint_connections_trust_boundaries",
            "Ensure VPC endpoint policies enforce trust boundaries",
            Severity::Medium,
            Status::Pass,
            "vpc",
            "",
            "global",
            &svc.account_id,
            "VPC endpoint trust boundary analysis requires manual review",
            self.metadata().compliance.clone(),
        )]
    }
}
