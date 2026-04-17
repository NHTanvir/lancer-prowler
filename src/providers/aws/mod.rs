pub mod checks;
pub mod services;

use anyhow::Context;
use aws_config::BehaviorVersion;

use crate::provider::Provider;

/// Standard AWS commercial partition regions.
/// Used as a default when the user does not specify --region.
const DEFAULT_AWS_REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ap-south-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "sa-east-1",
];

pub struct AwsProvider {
    /// Stored for use by service clients (IamService, etc.) in Week 3+.
    #[allow(dead_code)]
    pub config: aws_config::SdkConfig,
    pub account_id: String,
    pub regions: Vec<String>,
    pub identity_arn: String,
}

impl AwsProvider {
    pub async fn new(regions: Vec<String>) -> anyhow::Result<Self> {
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;

        let sts = aws_sdk_sts::Client::new(&config);
        let identity = sts
            .get_caller_identity()
            .send()
            .await
            .context("Failed to get AWS identity - are credentials configured?")?;

        let account_id = identity.account()
            .context("STS get_caller_identity returned no account ID")?
            .to_string();
        let identity_arn = identity.arn()
            .context("STS get_caller_identity returned no ARN")?
            .to_string();

        let resolved_regions = if regions.is_empty() {
            // No regions specified — use the standard commercial partition list.
            // (aws-sdk-ec2 was removed because it causes OOM on Windows during compilation.)
            DEFAULT_AWS_REGIONS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            regions
        };

        Ok(Self {
            config,
            account_id,
            regions: resolved_regions,
            identity_arn,
        })
    }
}

impl Provider for AwsProvider {
    fn name(&self) -> &str {
        "Amazon Web Services"
    }

    fn provider_id(&self) -> &str {
        "aws"
    }

    fn account_id(&self) -> &str {
        &self.account_id
    }

    fn regions(&self) -> Vec<String> {
        self.regions.clone()
    }
}
