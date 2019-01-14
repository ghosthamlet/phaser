#[derive(Debug, Default)]
pub struct Config {
    pub environment: String,
    pub aws_secret_access_key: String,
    pub aws_access_key_id: String,
    pub aws_region: String,
    pub aws_sqs_queue_api_to_phaser: String,
    pub aws_sqs_queue_phaser_to_api: String,
    pub aws_s3_bucket: String,
    pub assets_path: String,
}
