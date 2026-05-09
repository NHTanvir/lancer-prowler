pub struct GcpServiceAccount {
    pub email: String,
    pub name: String,
    pub display_name: String,
    pub disabled: bool,
    pub keys: Vec<ServiceAccountKey>,
}

pub struct ServiceAccountKey {
    pub key_id: String,
    pub key_type: String,     // "USER_MANAGED" | "SYSTEM_MANAGED"
    pub valid_after: String,
    pub valid_before: String,
}

pub struct GcpProjectIamBinding {
    pub role: String,
    pub members: Vec<String>,  // e.g. "user:foo@bar.com", "serviceAccount:...", "allUsers", "allAuthenticatedUsers"
}

pub struct GcpIamService {
    pub service_accounts: Vec<GcpServiceAccount>,
    pub project_bindings: Vec<GcpProjectIamBinding>,
    pub project_id: String,
}

impl GcpIamService {
    pub fn new_stub(project_id: String) -> Self {
        tracing::info!("GCP IAM service: stub mode");
        Self { service_accounts: vec![], project_bindings: vec![], project_id }
    }
}
