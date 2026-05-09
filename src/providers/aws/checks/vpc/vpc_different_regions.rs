use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::vpc::make_report;
use crate::providers::aws::services::vpc::VpcService;

pub struct VpcDifferentRegions;

impl Check for VpcDifferentRegions {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "vpc_different_regions".to_string(),
            name: "Ensure VPCs span multiple regions for resilience".to_string(),
            description: "Operating VPCs in a single region creates a single point of failure. \
                Multi-region deployments improve resilience and disaster recovery posture."
                .to_string(),
            severity: Severity::Medium,
            service: "vpc".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "CP-6".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<VpcService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;

        // In stub mode vpcs is always empty — emit a Pass with an explanatory note.
        if svc.vpcs.is_empty() {
            return vec![make_report(
                "vpc_different_regions",
                "Ensure VPCs span multiple regions for resilience",
                Severity::Medium,
                Status::Pass,
                "vpc",
                "",
                "global",
                account_id,
                "No VPC data available (stub mode — aws-sdk-ec2 not compiled on Windows)",
                self.metadata().compliance.clone(),
            )];
        }

        let regions: std::collections::HashSet<&str> =
            svc.vpcs.iter().map(|v| v.region.as_str()).collect();

        let (status, msg) = if regions.len() > 1 {
            (
                Status::Pass,
                format!(
                    "VPCs are deployed across {} region(s): {}",
                    regions.len(),
                    {
                        let mut r: Vec<&str> = regions.into_iter().collect();
                        r.sort_unstable();
                        r.join(", ")
                    }
                ),
            )
        } else {
            let region_name = regions.into_iter().next().unwrap_or("unknown");
            (
                Status::Fail,
                format!(
                    "All VPCs are deployed in a single region ({})",
                    region_name
                ),
            )
        };

        vec![make_report(
            "vpc_different_regions",
            "Ensure VPCs span multiple regions for resilience",
            Severity::Medium,
            status,
            "vpc",
            "",
            "global",
            account_id,
            &msg,
            self.metadata().compliance.clone(),
        )]
    }
}
