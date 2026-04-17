//! EC2 service — data model and stub fetcher.
//!
//! aws-sdk-ec2 v1.x contains 1000+ generated types and causes a stack overflow
//! during rustc compilation on Windows (MSVC linker + default stack size).
//! The data model is defined here manually; the fetcher returns empty data.
//! Real data collection can be enabled on Linux by adding aws-sdk-ec2 = "1"
//! to Cargo.toml and replacing the stub body.

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct IpPermission {
    /// "tcp", "udp", "icmp", "-1" (all traffic)
    pub ip_protocol: String,
    pub from_port: Option<i32>,
    pub to_port: Option<i32>,
    /// CIDR strings, e.g. "0.0.0.0/0"
    pub ip_ranges: Vec<String>,
    /// IPv6 CIDR strings, e.g. "::/0"
    pub ipv6_ranges: Vec<String>,
}

#[allow(dead_code)]
pub struct SecurityGroup {
    pub group_id: String,
    pub group_name: String,
    pub description: String,
    pub vpc_id: Option<String>,
    pub region: String,
    pub in_use: bool,
    pub ingress_rules: Vec<IpPermission>,
    pub egress_rules: Vec<IpPermission>,
}

#[allow(dead_code)]
pub struct EbsVolume {
    pub volume_id: String,
    pub arn: String,
    pub region: String,
    pub encrypted: bool,
    pub kms_key_id: Option<String>,
    pub state: String,
    /// Instance IDs this volume is attached to
    pub attachments: Vec<String>,
}

#[allow(dead_code)]
pub struct EbsSnapshot {
    pub snapshot_id: String,
    pub region: String,
    pub encrypted: bool,
    pub is_public: bool,
    pub owner_id: String,
}

#[allow(dead_code)]
pub struct Ec2Instance {
    pub instance_id: String,
    pub arn: String,
    pub region: String,
    pub instance_type: String,
    pub state: String,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    /// true when HttpTokens == "required" (IMDSv2 enforced)
    pub imdsv2_required: bool,
    pub monitoring_enabled: bool,
    pub ebs_optimized: bool,
    pub instance_profile_arn: Option<String>,
    /// Heuristic: true if user-data contains patterns that look like secrets
    pub user_data_has_secrets: bool,
    /// "hvm" or "paravirtual"
    pub virtualization_type: String,
    pub managed_by_ssm: bool,
    pub security_group_ids: Vec<String>,
    pub public_dns_name: Option<String>,
}

#[allow(dead_code)]
pub struct Ami {
    pub image_id: String,
    pub region: String,
    pub name: String,
    pub public: bool,
    pub owner_id: String,
}

#[allow(dead_code)]
pub struct ElasticIp {
    pub allocation_id: String,
    pub public_ip: String,
    pub region: String,
    pub associated_instance_id: Option<String>,
    pub associated_network_interface_id: Option<String>,
}

// ── Service ───────────────────────────────────────────────────────────────────

pub struct Ec2Service {
    pub security_groups: Vec<SecurityGroup>,
    pub instances: Vec<Ec2Instance>,
    pub ebs_volumes: Vec<EbsVolume>,
    pub ebs_snapshots: Vec<EbsSnapshot>,
    pub amis: Vec<Ami>,
    pub elastic_ips: Vec<ElasticIp>,
    /// True when the account-level EBS default encryption setting is enabled
    pub ebs_default_encryption_enabled: bool,
    pub account_id: String,
    pub regions: Vec<String>,
}

impl Ec2Service {
    /// Create a new Ec2Service.
    ///
    /// Currently returns an empty stub because aws-sdk-ec2 cannot be compiled
    /// on Windows (stack overflow in rustc). Real data fetching can be enabled
    /// on Linux once the SDK crate is added.
    pub async fn new(
        _config: &aws_config::SdkConfig,
        account_id: String,
        regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        tracing::info!(
            "EC2 service: stub mode (aws-sdk-ec2 not compiled on Windows). \
             {} region(s) in scope.",
            regions.len()
        );
        Ok(Self {
            security_groups: vec![],
            instances: vec![],
            ebs_volumes: vec![],
            ebs_snapshots: vec![],
            amis: vec![],
            elastic_ips: vec![],
            ebs_default_encryption_enabled: false,
            account_id,
            regions,
        })
    }
}
