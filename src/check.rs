pub trait Check: Send + Sync {
    fn metadata(&self) -> &crate::models::CheckMetadata;
    fn execute(&self, context: &dyn std::any::Any) -> Vec<crate::models::CheckReport>;
}
