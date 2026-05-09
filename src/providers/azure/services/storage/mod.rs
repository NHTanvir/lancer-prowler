pub struct StorageAccount {
    pub id: String,
    pub name: String,
    pub resource_group: String,
    pub location: String,
    pub kind: String,
    pub sku_name: String,
    pub https_traffic_only: bool,
    pub tls_version: String,
    pub blob_public_access: bool,
    pub network_default_action: String,
    pub encryption_key_source: String,
    pub infrastructure_encryption: bool,
    pub blob_soft_delete_enabled: bool,
    pub container_soft_delete_enabled: bool,
    pub versioning_enabled: bool,
    pub shared_key_access_enabled: bool,
}

pub struct StorageService {
    pub accounts: Vec<StorageAccount>,
    pub subscription_id: String,
}

impl StorageService {
    pub fn new_stub(subscription_id: String) -> Self {
        tracing::info!("Azure StorageService: stub mode");
        Self { accounts: vec![], subscription_id }
    }
}
