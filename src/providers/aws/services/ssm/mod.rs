//! SSM service — stub (SSM checks are handled via EC2 managed_by_ssm field).

#[allow(dead_code)]
pub struct SsmService {
    pub account_id: String,
}

impl SsmService {
    pub async fn new(
        _config: &aws_config::SdkConfig,
        account_id: String,
        _regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self { account_id })
    }
}
