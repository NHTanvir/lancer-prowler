#[allow(dead_code)]
pub trait Provider: Send + Sync {
    fn name(&self) -> &str;
    fn provider_id(&self) -> &str;
    fn account_id(&self) -> &str;
    fn regions(&self) -> Vec<String>;
}
