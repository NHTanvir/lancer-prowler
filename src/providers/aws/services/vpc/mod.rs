//! VPC service — stub mode (aws-sdk-ec2 not compiled on Windows due to MSVC stack overflow).
//! Enable on Linux by pulling in aws-sdk-ec2 and implementing the fetchers.

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct Vpc {
    pub vpc_id: String,
    pub region: String,
    pub is_default: bool,
    pub cidr_block: String,
    pub flow_logs_enabled: bool,
}

#[allow(dead_code)]
pub struct Subnet {
    pub subnet_id: String,
    pub vpc_id: String,
    pub region: String,
    /// Whether the subnet auto-assigns public IPs on launch.
    pub map_public_ip_on_launch: bool,
    pub available_ip_count: i32,
}

#[allow(dead_code)]
pub struct VpcPeeringConnection {
    pub connection_id: String,
    pub requester_vpc_id: String,
    pub accepter_vpc_id: String,
    pub requester_account_id: String,
    pub accepter_account_id: String,
    pub region: String,
    /// Whether routing allows least-privilege (overlapping routes are a risk).
    pub has_overlapping_route: bool,
}

#[allow(dead_code)]
pub struct VpcService {
    pub vpcs: Vec<Vpc>,
    pub subnets: Vec<Subnet>,
    pub peering_connections: Vec<VpcPeeringConnection>,
    pub account_id: String,
}

// ── VpcService::new ───────────────────────────────────────────────────────────

impl VpcService {
    pub async fn new(
        _config: &aws_config::SdkConfig,
        account_id: String,
        _regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        tracing::info!(
            "VPC service: stub mode (aws-sdk-ec2 not compiled on Windows)"
        );
        Ok(Self {
            vpcs: vec![],
            subnets: vec![],
            peering_connections: vec![],
            account_id,
        })
    }
}
