pub struct NetworkPolicy {
    pub name: String,
    pub namespace: String,
    pub pod_selector_empty: bool,  // selects all pods if true
    pub ingress_rules: Vec<NetworkPolicyRule>,
    pub egress_rules: Vec<NetworkPolicyRule>,
}

pub struct NetworkPolicyRule {
    pub from_namespaces: Vec<String>,
    pub from_pod_selectors: Vec<String>,
    pub ports: Vec<String>,
}

pub struct NetworkService {
    pub network_policies: Vec<NetworkPolicy>,
    pub namespaces_without_network_policy: Vec<String>,
    pub cluster_name: String,
}

impl NetworkService {
    pub fn new_stub(cluster_name: String) -> Self {
        tracing::info!("Kubernetes Network service: stub mode");
        Self { network_policies: vec![], namespaces_without_network_policy: vec![], cluster_name }
    }
}
