pub struct KeyVault {
    pub id: String,
    pub name: String,
    pub resource_group: String,
    pub location: String,
    pub sku_name: String,
    pub soft_delete_enabled: bool,
    pub purge_protection_enabled: bool,
    pub public_network_access: String,
    pub rbac_authorization: bool,
    pub network_default_action: String,
}

pub struct KeyVaultService {
    pub vaults: Vec<KeyVault>,
    pub subscription_id: String,
}

impl KeyVaultService {
    pub fn new_stub(subscription_id: String) -> Self {
        tracing::info!("Azure KeyVaultService: stub mode");
        Self { vaults: vec![], subscription_id }
    }
}
