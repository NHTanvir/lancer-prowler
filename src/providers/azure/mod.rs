use crate::provider::Provider;

pub mod services;
pub mod checks;

pub struct AzureProvider {
    pub subscription_id: String,
    pub tenant_id: String,
    pub regions: Vec<String>,
}

impl AzureProvider {
    pub fn new_stub(subscription_id: String) -> Self {
        Self {
            subscription_id,
            tenant_id: "unknown".to_string(),
            regions: vec![
                "eastus".to_string(),
                "westus".to_string(),
                "westeurope".to_string(),
            ],
        }
    }
}

impl Provider for AzureProvider {
    fn name(&self) -> &str { "Microsoft Azure" }
    fn provider_id(&self) -> &str { "azure" }
    fn account_id(&self) -> &str { &self.subscription_id }
    fn regions(&self) -> Vec<String> { self.regions.clone() }
}
