//! Captcha handlers

use axum::{
    extract::State,
    Json,
};
use chrono::Utc;

use crate::captcha::{generate_captcha_image, verify_captcha};
use crate::error::{AppError, AppResult};
use crate::models::{AppState, CaptchaResponse};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct VerifyCaptchaRequest {
    pub captcha_id: String,
    pub answer: String,
}

/// Generate a new captcha
pub async fn get_captcha(
    State(state): State<AppState>,
) -> AppResult<Json<CaptchaResponse>> {
    let (id, answer, image_base64) = generate_captcha_image(state.config.captcha_difficulty)?;
    
    // Store captcha in database
    let now = Utc::now();
    let expires_at = now + chrono::Duration::minutes(5);
    
    sqlx::query(
        "INSERT INTO captcha_sessions (id, answer, created_at, expires_at) VALUES (?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&answer)
    .bind(now.to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;
    
    Ok(Json(CaptchaResponse {
        captcha_id: id,
        image: image_base64,
    }))
}

/// Verify captcha answer
pub async fn verify_captcha_endpoint(
    State(state): State<AppState>,
    Json(payload): Json<VerifyCaptchaRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Get stored captcha
    let stored_answer: Option<String> = sqlx::query_scalar(
        "SELECT answer FROM captcha_sessions WHERE id = ? AND expires_at > ?"
    )
    .bind(&payload.captcha_id)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;
    
    let expected = stored_answer
        .ok_or_else(|| AppError::Captcha("Invalid or expired captcha".to_string()))?;
    
    let valid = verify_captcha(&payload.answer, &expected)?;
    
    if valid {
        // Delete used captcha
        sqlx::query("DELETE FROM captcha_sessions WHERE id = ?")
            .bind(&payload.captcha_id)
            .execute(&state.pool)
            .await
            .ok();
    }
    
    Ok(Json(serde_json::json!({
        "valid": valid
    })))
}
