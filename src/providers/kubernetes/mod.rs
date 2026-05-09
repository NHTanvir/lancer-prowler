use crate::provider::Provider;

pub mod services;
pub mod checks;

pub struct KubernetesProvider {
    pub cluster_name: String,
    pub context: String,
    pub regions: Vec<String>,
}

impl KubernetesProvider {
    pub fn new_stub(cluster_name: String) -> Self {
        Self {
            cluster_name,
            context: "default".to_string(),
            regions: vec!["cluster".to_string()],
        }
    }
}

impl Provider for KubernetesProvider {
    fn name(&self) -> &str { "Kubernetes" }
    fn provider_id(&self) -> &str { "kubernetes" }
    fn account_id(&self) -> &str { &self.cluster_name }
    fn regions(&self) -> Vec<String> { self.regions.clone() }
}
