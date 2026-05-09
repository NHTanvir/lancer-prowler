pub struct GcpBucket {
    pub name: String,
    pub location: String,
    pub storage_class: String,
    pub uniform_bucket_level_access: bool,  // IAM-only, no legacy ACLs
    pub public_access_prevention: String,    // "enforced" | "inherited"
    pub versioning_enabled: bool,
    pub logging_enabled: bool,
    pub retention_policy_locked: bool,
    pub kms_key_name: Option<String>,
    pub labels: std::collections::HashMap<String, String>,
}

pub struct GcpStorageService {
    pub buckets: Vec<GcpBucket>,
    pub project_id: String,
}

impl GcpStorageService {
    pub fn new_stub(project_id: String) -> Self {
        tracing::info!("GCP Storage service: stub mode");
        Self { buckets: vec![], project_id }
    }
}
