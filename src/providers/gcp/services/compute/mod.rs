pub struct GcpInstance {
    pub name: String,
    pub id: String,
    pub zone: String,
    pub machine_type: String,
    pub status: String,
    pub can_ip_forward: bool,
    pub serial_port_enabled: bool,
    pub oslogin_enabled: bool,
    pub shielded_vm_enabled: bool,
    pub public_ip: Option<String>,
    pub service_account_email: Option<String>,
    pub service_account_scopes: Vec<String>,
    pub disk_auto_delete: bool,
    pub boot_disk_encrypted: bool,
}

pub struct GcpFirewallRule {
    pub name: String,
    pub direction: String,    // "INGRESS" | "EGRESS"
    pub priority: i32,
    pub disabled: bool,
    pub source_ranges: Vec<String>,
    pub allowed_ports: Vec<FirewallPortRule>,
}

pub struct FirewallPortRule {
    pub ip_protocol: String,
    pub ports: Vec<String>,
}

pub struct GcpComputeService {
    pub instances: Vec<GcpInstance>,
    pub firewall_rules: Vec<GcpFirewallRule>,
    pub project_id: String,
}

impl GcpComputeService {
    pub fn new_stub(project_id: String) -> Self {
        tracing::info!("GCP Compute service: stub mode");
        Self { instances: vec![], firewall_rules: vec![], project_id }
    }
}
