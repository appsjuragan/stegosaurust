//! Application Configuration

use anyhow::Result;

#[derive(Clone, Debug)]
pub struct Config {
    pub jwt_secret: String,
    pub jwt_expiration: i64,
    pub captcha_difficulty: usize,
    pub max_upload_size: usize,
    #[allow(dead_code)]
    pub allowed_image_types: Vec<String>,
    pub cors_origin: String,
    pub server_host: String,
    pub server_port: u16,
    pub data_dir: String,
    // MinIO / S3
    pub minio_endpoint: String,
    pub minio_access_key: String,
    pub minio_secret_key: String,
    pub minio_bucket: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "super-secret-key-change-in-production".to_string()),
            jwt_expiration: std::env::var("JWT_EXPIRATION")
                .unwrap_or_else(|_| "86400".to_string())
                .parse()?,
            captcha_difficulty: std::env::var("CAPTCHA_DIFFICULTY")
                .unwrap_or_else(|_| "5".to_string())
                .parse()?,
            max_upload_size: std::env::var("MAX_UPLOAD_SIZE")
                .unwrap_or_else(|_| "10485760".to_string()) // 10MB
                .parse()?,
            allowed_image_types: vec![
                "image/png".to_string(),
                "image/jpeg".to_string(),
                "image/webp".to_string(),
            ],
            cors_origin: std::env::var("CORS_ORIGIN")
                .unwrap_or_else(|_| "*".to_string()),
            server_host: std::env::var("SERVER_HOST")
                .unwrap_or_else(|_| "0.0.0.0".to_string()),
            server_port: std::env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
            data_dir: std::env::var("DATA_DIR")
                .unwrap_or_else(|_| "./data".to_string()),
            minio_endpoint: std::env::var("MINIO_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:9000".to_string()),
            minio_access_key: std::env::var("MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            minio_secret_key: std::env::var("MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".to_string()),
            minio_bucket: std::env::var("MINIO_BUCKET")
                .unwrap_or_else(|_| "stegano".to_string()),
        })
    }
}
