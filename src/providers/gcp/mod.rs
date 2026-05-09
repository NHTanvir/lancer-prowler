use crate::provider::Provider;

pub mod services;
pub mod checks;

pub struct GcpProvider {
    pub project_id: String,
    pub regions: Vec<String>,
}

impl GcpProvider {
    pub fn new_stub(project_id: String) -> Self {
        Self {
            project_id,
            regions: vec![
                "us-central1".to_string(), "us-east1".to_string(),
                "europe-west1".to_string(), "asia-east1".to_string(),
            ],
        }
    }
}

impl Provider for GcpProvider {
    fn name(&self) -> &str { "Google Cloud Platform" }
    fn provider_id(&self) -> &str { "gcp" }
    fn account_id(&self) -> &str { &self.project_id }
    fn regions(&self) -> Vec<String> { self.regions.clone() }
}
