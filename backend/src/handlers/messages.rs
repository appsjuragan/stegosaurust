use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    http::header,
    Extension,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};


use crate::error::{AppError, AppResult};
use crate::models::{AppState, Claims, MessageListItem};

#[derive(Debug, Serialize)]
pub struct MessageDetail {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub has_stegano: bool,
    pub original_filename: Option<String>,
    pub encrypted_data: String,
    pub seed_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct DecryptMessageRequest {
    pub seed_words: String,
}

#[derive(Debug, Serialize)]
pub struct DecryptMessageResponse {
    pub decrypted_text: String,
}

/// List all messages for the current user
pub async fn list_messages(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> AppResult<Json<Vec<MessageListItem>>> {
    let messages: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT id, created_at, original_filename, stegano_image_path
        FROM messages
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 100
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    let items: Vec<MessageListItem> = messages
        .into_iter()
        .map(|(id, created_at_str, original_filename, stegano_path)| {
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            MessageListItem {
                id,
                created_at,
                has_stegano: stegano_path.is_some(),
                original_filename,
            }
        })
        .collect();

    Ok(Json(items))
}

/// Get a specific message
pub async fn get_message(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> AppResult<Json<MessageDetail>> {
    let message: Option<(String, String, Option<String>, Option<String>, String, String)> = 
        sqlx::query_as(
            r#"
            SELECT id, created_at, original_filename, stegano_image_path, encrypted_data, seed_hash
            FROM messages
            WHERE id = ? AND user_id = ?
            "#,
        )
        .bind(&id)
        .bind(&claims.sub)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| AppError::Database(e))?;

    let (msg_id, created_at_str, original_filename, stegano_path, encrypted_data, seed_hash) =
        message.ok_or_else(|| AppError::NotFound("Message not found".to_string()))?;

    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    Ok(Json(MessageDetail {
        id: msg_id,
        created_at,
        has_stegano: stegano_path.is_some(),
        original_filename,
        encrypted_data,
        seed_hash,
    }))
}

/// Get the steganography image for a message
pub async fn get_message_image(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    // Check ownership and get path
    let stegano_path: Option<Option<String>> = sqlx::query_scalar(
        "SELECT stegano_image_path FROM messages WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    let path_opt = stegano_path
        .ok_or_else(|| AppError::NotFound("Message not found".to_string()))?;

    let path_str = path_opt
        .ok_or_else(|| AppError::NotFound("No image associated with this message".to_string()))?;

    // Read file from S3
    let result = state.storage.get_object(&path_str).await
        .map_err(|e| AppError::Stegano(format!("Failed to retrieve image from S3: {}", e)))?;
        
    let file_bytes = result.to_vec();

    // Determine content type from extension
    let lower_path = path_str.to_lowercase();
    let content_type = if lower_path.ends_with(".png") {
        "image/png"
    } else if lower_path.ends_with(".jpg") || lower_path.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower_path.ends_with(".webp") {
        "image/webp"
    } else {
        "application/octet-stream"
    };

    // Return response
    Ok((
        [(header::CONTENT_TYPE, content_type)],
        file_bytes,
    ).into_response())
}

/// Delete a message
pub async fn delete_message(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    // Verify ownership and get image path
    let message: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, stegano_image_path FROM messages WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    let (_, stegano_path) = message.ok_or_else(|| AppError::NotFound("Message not found".to_string()))?;

    // Delete the message from DB
    sqlx::query("DELETE FROM messages WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::Database(e))?;

    // If successful, delete file from S3
    if let Some(path) = stegano_path {
        let _ = state.storage.delete_object(&path).await;
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Message deleted"
    })))
}

/// Decrypt a message with seed words
pub async fn decrypt_message(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<DecryptMessageRequest>,
) -> AppResult<Json<DecryptMessageResponse>> {
    // Get the encrypted data
    let encrypted_data: Option<String> = sqlx::query_scalar(
        "SELECT encrypted_data FROM messages WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    let encrypted = encrypted_data
        .ok_or_else(|| AppError::NotFound("Message not found".to_string()))?;

    // Decrypt
    let decrypted = crate::crypto::decrypt_text(&encrypted, &payload.seed_words)?;

    Ok(Json(DecryptMessageResponse {
        decrypted_text: decrypted,
    }))
}
