//! Steganography handlers

use axum::{
    extract::{Multipart, State},
    Extension,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{encrypt_text, hash_seed_words};
use crate::error::{AppError, AppResult};
use crate::models::{AppState, Claims};
use crate::stegano::{embed_message as stegano_embed, extract_message as stegano_extract};

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct EmbedRequestMultipart {
    pub image_format: String,
    pub message: String,
    pub seed_words: String,
}

#[derive(Debug, Serialize)]
pub struct EmbedResponseJson {
    pub image_data: String,
    pub original_filename: String,
    pub metadata_used: bool,
    pub overflow_size: usize,
    pub message_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ExtractRequestJson {
    pub image_data: String,
    pub image_format: String,
    pub seed_words: String,
}

#[derive(Debug, Serialize)]
pub struct ExtractResponseJson {
    pub message: String,
    pub was_encrypted: bool,
}

#[derive(Debug, Deserialize)]
pub struct DetectRequestJson {
    pub image_data: String,
    pub image_format: String,
}

#[derive(Debug, Serialize)]
pub struct DetectResponseJson {
    pub has_stegano: bool,
}

/// Embed message into image using steganography
pub async fn embed_message_handler(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    mut multipart: Multipart,
) -> AppResult<Json<EmbedResponseJson>> {
    let mut image_data: Option<Vec<u8>> = None;
    let mut image_format: Option<String> = None;
    let mut message: Option<String> = None;
    let mut seed_words: Option<String> = None;
    let mut original_filename = "image".to_string();

    // Parse multipart form data
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        AppError::Validation(format!("Failed to parse multipart: {}", e))
    })? {
        let name = field.name().unwrap_or("").to_string();
        
        match name.as_str() {
            "image" => {
                original_filename = field
                    .file_name()
                    .unwrap_or("image")
                    .to_string();
                
                let data = field.bytes().await.map_err(|e| {
                    AppError::Validation(format!("Failed to read image: {}", e))
                })?;
                image_data = Some(data.to_vec());
                
                // Detect format from filename
                if original_filename.to_lowercase().ends_with(".png") {
                    image_format = Some("png".to_string());
                } else if original_filename.to_lowercase().ends_with(".jpg")
                    || original_filename.to_lowercase().ends_with(".jpeg")
                {
                    image_format = Some("jpg".to_string());
                } else if original_filename.to_lowercase().ends_with(".webp") {
                    image_format = Some("webp".to_string());
                }
            }
            "format" => {
                let data = field.bytes().await.map_err(|e| {
                    AppError::Validation(format!("Failed to read format: {}", e))
                })?;
                image_format = Some(String::from_utf8_lossy(&data).to_string());
            }
            "message" => {
                let data = field.bytes().await.map_err(|e| {
                    AppError::Validation(format!("Failed to read message: {}", e))
                })?;
                message = Some(String::from_utf8_lossy(&data).to_string());
            }
            "seed_words" => {
                let data = field.bytes().await.map_err(|e| {
                    AppError::Validation(format!("Failed to read seed words: {}", e))
                })?;
                seed_words = Some(String::from_utf8_lossy(&data).to_string());
            }
            _ => {}
        }
    }

    // Validate required fields
    let image_data = image_data.ok_or_else(|| {
        AppError::Validation("Image is required".to_string())
    })?;
    
    let format = image_format.ok_or_else(|| {
        AppError::Validation("Image format is required".to_string())
    })?;
    
    let message = message.ok_or_else(|| {
        AppError::Validation("Message is required".to_string())
    })?;
    
    let seed_words = seed_words.ok_or_else(|| {
        AppError::Validation("Seed words are required".to_string())
    })?;

    // Validate format
    if !["png", "jpg", "jpeg", "webp"].contains(&format.to_lowercase().as_str()) {
        return Err(AppError::Validation(
            "Invalid format. Supported: png, jpg, webp".to_string(),
        ));
    }

    // Embed message
    let (stego_image, metadata_used, overflow_size) = 
        stegano_embed(&image_data, &message, &seed_words, &format)?;

    // Store record in database
    let now = Utc::now();
    let message_id = Uuid::new_v4().to_string();
    let seed_hash = hash_seed_words(&seed_words);

    // Upload stego image to MinIO/S3
    let object_path = format!("{}/stegano_{}.{}", claims.sub, message_id, format);
    let stego_bytes = STANDARD.decode(&stego_image)
        .map_err(|e| AppError::Stegano(format!("Failed to decode stego image: {}", e)))?;
    
    // Determine content type
    let content_type = match format.to_lowercase().as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    };

    // Upload
    state.storage
        .put_object_with_content_type(&object_path, &stego_bytes, content_type)
        .await
        .map_err(|e| AppError::Stegano(format!("Failed to upload to S3: {}", e)))?;
        
    let stegano_image_path = Some(object_path);

    // Encrypt the message for storage
    let encrypted_data = encrypt_text(&message, &seed_words)?;

    sqlx::query(
        r#"
        INSERT INTO messages (id, user_id, encrypted_data, seed_hash, original_filename, stegano_image_path, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&message_id)
    .bind(&claims.sub)
    .bind(&encrypted_data)
    .bind(&seed_hash)
    .bind(&original_filename)
    .bind(&stegano_image_path)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(&state.pool)
    .await?;

    Ok(Json(EmbedResponseJson {
        image_data: stego_image,
        original_filename,
        metadata_used,
        overflow_size,
        message_id,
    }))
}

/// Extract message from steganographic image
pub async fn extract_message_handler(
    State(_state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Json(payload): Json<ExtractRequestJson>,
) -> AppResult<Json<ExtractResponseJson>> {
    // Decode base64 image
    let image_data = STANDARD
        .decode(&payload.image_data)
        .map_err(|e| AppError::Validation(format!("Invalid base64 image: {}", e)))?;

    // Extract message
    let message = stegano_extract(&image_data, &payload.seed_words, &payload.image_format)?;

    Ok(Json(ExtractResponseJson {
        message,
        was_encrypted: true,
    }))
}

/// Detect steganography content in image
pub async fn detect_stegano_handler(
    State(_state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Json(payload): Json<DetectRequestJson>,
) -> AppResult<Json<DetectResponseJson>> {
    // Decode base64 image
    let image_data = STANDARD
        .decode(&payload.image_data)
        .map_err(|e| AppError::Validation(format!("Invalid base64 image: {}", e)))?;

    // Detect content
    let has_stegano = crate::stegano::detect_stegano_content(&image_data, &payload.image_format)?;

    Ok(Json(DetectResponseJson { has_stegano }))
}


