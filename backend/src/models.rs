//! Data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use validator::Validate;

use crate::config::Config;

use s3::Bucket;

// Application state
#[derive(Clone, Debug)]
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub config: Config,
    pub storage: Bucket,
}

// Database models
#[allow(dead_code)]
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub user_id: String,
    pub encrypted_data: String,
    pub seed_hash: String,
    pub original_filename: Option<String>,
    pub stegano_image_path: Option<String>,
    pub metadata_overflow: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct CaptchaSession {
    pub id: String,
    pub answer: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

// Request/Response DTOs
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 32), regex(path = "crate::models::USERNAME_REGEX"))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    pub captcha_id: String,
    pub captcha_answer: String,
}

lazy_static::lazy_static! {
    static ref USERNAME_REGEX: regex::Regex = regex::Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 1))]
    pub username: String,
    #[validate(length(min = 1))]
    pub password: String,
    pub captcha_id: String,
    pub captcha_answer: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_in: i64,
    pub user: UserInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    pub text: String,
    pub seed_words: String,
}

#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    pub encrypted_data: String,
    pub seed_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    pub encrypted_data: String,
    pub seed_words: String,
}

#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    pub decrypted_text: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct EmbedRequest {
    pub image_format: String, // png, jpg, webp
    pub message: String,
    pub seed_words: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct EmbedResponse {
    pub image_data: String, // Base64 encoded
    pub original_filename: String,
    pub metadata_used: bool,
    pub overflow_size: usize,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ExtractRequest {
    pub seed_words: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct ExtractResponse {
    pub message: String,
    pub was_encrypted: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct QRCodeRequest {
    pub data: String,
    pub size: Option<u32>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct QRCodeResponse {
    pub qr_image: String, // Base64 encoded PNG
    pub data: String,
}


#[derive(Debug, Serialize)]
pub struct CaptchaResponse {
    pub captcha_id: String,
    pub image: String, // Base64 encoded image
}

#[derive(Debug, Serialize)]
pub struct MessageListItem {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub has_stegano: bool,
    pub original_filename: Option<String>,
}

// JWT Claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID
    pub username: String,
    pub exp: i64,
    pub iat: i64,
}

// Sanitization helper
pub fn sanitize_input(input: &str) -> String {
    // Remove potentially dangerous characters
    let sanitized = input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect::<String>();
    
    // Limit length
    sanitized.chars().take(10000).collect()
}

#[allow(dead_code)]
pub fn sanitize_filename(filename: &str) -> String {
    let sanitized = filename
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect::<String>();
    
    sanitized.chars().take(255).collect()
}
