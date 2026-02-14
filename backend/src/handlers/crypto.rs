//! Encryption/decryption handlers

use axum::{
    extract::State,
    Extension,
    Json,
};
use chrono::Utc;
use uuid::Uuid;

use crate::crypto::{decrypt_text as crypto_decrypt, encrypt_text as crypto_encrypt, hash_seed_words};
use crate::error::AppResult;
use crate::models::{
    AppState, Claims, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse,
};

/// Encrypt text with seed words
pub async fn encrypt_text_handler(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<EncryptRequest>,
) -> AppResult<Json<EncryptResponse>> {
    // Validate input
    if payload.text.is_empty() {
        return Err(crate::error::AppError::Validation(
            "Text cannot be empty".to_string(),
        ));
    }

    if payload.seed_words.trim().is_empty() {
        return Err(crate::error::AppError::Validation(
            "Seed words cannot be empty".to_string(),
        ));
    }

    // Limit text size
    if payload.text.len() > 100_000 {
        return Err(crate::error::AppError::Validation(
            "Text too large (max 100KB)".to_string(),
        ));
    }

    // Encrypt the text
    let encrypted_data = crypto_encrypt(&payload.text, &payload.seed_words)?;
    let seed_hash = hash_seed_words(&payload.seed_words);

    // Store in database
    let now = Utc::now();
    let message_id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO messages (id, user_id, encrypted_data, seed_hash, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&message_id)
    .bind(&claims.sub)
    .bind(&encrypted_data)
    .bind(&seed_hash)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(&state.pool)
    .await?;

    Ok(Json(EncryptResponse {
        encrypted_data,
        seed_hash,
    }))
}

/// Decrypt text with seed words
pub async fn decrypt_text_handler(
    State(_state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Json(payload): Json<DecryptRequest>,
) -> AppResult<Json<DecryptResponse>> {
    // Validate input
    if payload.encrypted_data.is_empty() {
        return Err(crate::error::AppError::Validation(
            "Encrypted data cannot be empty".to_string(),
        ));
    }

    if payload.seed_words.trim().is_empty() {
        return Err(crate::error::AppError::Validation(
            "Seed words cannot be empty".to_string(),
        ));
    }

    // Decrypt the text
    let decrypted_text = crypto_decrypt(&payload.encrypted_data, &payload.seed_words)?;

    Ok(Json(DecryptResponse { decrypted_text }))
}

