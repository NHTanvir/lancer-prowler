pub struct VirtualMachine {
    pub id: String,
    pub name: String,
    pub resource_group: String,
    pub location: String,
    pub vm_size: String,
    pub os_type: String,
    pub os_disk_encryption: bool,
    pub data_disks_encrypted: bool,
    pub managed_identity_enabled: bool,
    pub boot_diagnostics_enabled: bool,
    pub availability_zone: Option<String>,
    pub patch_mode: String,
}

pub struct ComputeService {
    pub virtual_machines: Vec<VirtualMachine>,
    pub subscription_id: String,
}

impl ComputeService {
    pub fn new_stub(subscription_id: String) -> Self {
        tracing::info!("Azure ComputeService: stub mode");
        Self { virtual_machines: vec![], subscription_id }
    }
}
