pub struct ClusterRole {
    pub name: String,
    pub rules: Vec<PolicyRule>,
    pub is_cluster_admin_equivalent: bool,  // has wildcard verbs on * resources
}

pub struct PolicyRule {
    pub api_groups: Vec<String>,
    pub resources: Vec<String>,
    pub verbs: Vec<String>,
    pub resource_names: Vec<String>,
}

pub struct ClusterRoleBinding {
    pub name: String,
    pub role_ref_name: String,
    pub subjects: Vec<Subject>,
}

pub struct Subject {
    pub kind: String,   // "User", "Group", "ServiceAccount"
    pub name: String,
    pub namespace: Option<String>,
}

pub struct RbacService {
    pub cluster_roles: Vec<ClusterRole>,
    pub cluster_role_bindings: Vec<ClusterRoleBinding>,
    pub cluster_name: String,
}

impl RbacService {
    pub fn new_stub(cluster_name: String) -> Self {
        tracing::info!("Kubernetes RBAC service: stub mode");
        Self { cluster_roles: vec![], cluster_role_bindings: vec![], cluster_name }
    }
}
