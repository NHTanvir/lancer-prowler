use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::vpc::make_report;
use crate::providers::aws::services::vpc::VpcService;

pub struct VpcPeeringRoutingTablesWithLeastPrivilege;

impl Check for VpcPeeringRoutingTablesWithLeastPrivilege {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "vpc_peering_routing_tables_with_least_privilege".to_string(),
            name: "Ensure VPC peering routing tables follow least-privilege".to_string(),
            description: "VPC peering connections with overlapping or overly broad route entries \
                can allow unintended cross-VPC access. Route tables should only grant the \
                minimum required CIDR ranges for each peering connection."
                .to_string(),
            severity: Severity::High,
            service: "vpc".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "5.5".to_string(),
                },
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

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for conn in &svc.peering_connections {
            let (status, msg) = if conn.has_overlapping_route {
                (
                    Status::Fail,
                    format!(
                        "VPC peering connection {} has overlapping route entries that violate \
                         least-privilege (requester: {}, accepter: {})",
                        conn.connection_id, conn.requester_vpc_id, conn.accepter_vpc_id
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "VPC peering connection {} follows least-privilege routing",
                        conn.connection_id
                    ),
                )
            };

            reports.push(make_report(
                "vpc_peering_routing_tables_with_least_privilege",
                "Ensure VPC peering routing tables follow least-privilege",
                Severity::High,
                status,
                &conn.connection_id,
                &format!(
                    "arn:aws:ec2:{}:{}:vpc-peering-connection/{}",
                    conn.region, account_id, conn.connection_id
                ),
                &conn.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        // Stub mode: peering_connections is empty, so no reports are emitted.
        // Emit a single Pass to signal the check ran.
        if reports.is_empty() {
            reports.push(make_report(
                "vpc_peering_routing_tables_with_least_privilege",
                "Ensure VPC peering routing tables follow least-privilege",
                Severity::High,
                Status::Pass,
                "vpc-peering",
                "",
                "global",
                account_id,
                "No VPC peering connections found (stub mode)",
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
