//! Authentication handlers

use axum::{
    extract::State,
    Json,
};
use chrono::Utc;
use uuid::Uuid;
use validator::Validate;

use crate::auth::{generate_token, hash_password, verify_password};
use crate::captcha::verify_captcha;
use crate::error::{AppError, AppResult};
use crate::models::{
    AppState, AuthResponse, LoginRequest, RegisterRequest, UserInfo,
};

/// Register a new user
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> AppResult<Json<AuthResponse>> {
    // Validate input
    payload.validate().map_err(|e| {
        AppError::Validation(format!("Validation error: {}", e))
    })?;

    // Sanitize inputs
    let username = crate::models::sanitize_input(&payload.username);
    let email = crate::models::sanitize_input(&payload.email);

    // Verify captcha
    let captcha_answer: Option<String> = sqlx::query_scalar(
        "SELECT answer FROM captcha_sessions WHERE id = ? AND expires_at > ?"
    )
    .bind(&payload.captcha_id)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    let expected_answer = captcha_answer
        .ok_or_else(|| AppError::Captcha("Invalid or expired captcha".to_string()))?;

    if !verify_captcha(&payload.captcha_answer, &expected_answer)? {
        return Err(AppError::Captcha("Incorrect captcha answer".to_string()));
    }

    // Delete used captcha
    sqlx::query("DELETE FROM captcha_sessions WHERE id = ?")
        .bind(&payload.captcha_id)
        .execute(&state.pool)
        .await
        .ok();

    // Check if username exists
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)")
        .bind(&username)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::Database(e))?;

    if exists {
        return Err(AppError::Validation("Username already exists".to_string()));
    }

    // Check if email exists
    let email_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)")
        .bind(&email)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::Database(e))?;

    if email_exists {
        return Err(AppError::Validation("Email already registered".to_string()));
    }

    // Hash password
    let password_hash = hash_password(&payload.password)?;

    // Create user
    let now = Utc::now();
    let user_id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&user_id)
    .bind(&username)
    .bind(&email)
    .bind(&password_hash)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    // Generate JWT token
    let (token, expires_in) = generate_token(&user_id, &username, &state.config)?;

    Ok(Json(AuthResponse {
        token,
        expires_in,
        user: UserInfo {
            id: user_id,
            username,
            email,
        },
    }))
}

/// Login user
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    // Validate input
    payload.validate().map_err(|e| {
        AppError::Validation(format!("Validation error: {}", e))
    })?;

    // Sanitize username
    let username = crate::models::sanitize_input(&payload.username);

    // Verify captcha
    let captcha_answer: Option<String> = sqlx::query_scalar(
        "SELECT answer FROM captcha_sessions WHERE id = ? AND expires_at > ?"
    )
    .bind(&payload.captcha_id)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    let expected_answer = captcha_answer
        .ok_or_else(|| AppError::Captcha("Invalid or expired captcha".to_string()))?;

    if !verify_captcha(&payload.captcha_answer, &expected_answer)? {
        return Err(AppError::Captcha("Incorrect captcha answer".to_string()));
    }

    // Delete used captcha
    sqlx::query("DELETE FROM captcha_sessions WHERE id = ?")
        .bind(&payload.captcha_id)
        .execute(&state.pool)
        .await
        .ok();

    // Find user
    let user: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, username, email, password_hash FROM users WHERE username = ?"
    )
    .bind(&username)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    let (user_id, username, email, password_hash) = user
        .ok_or_else(|| AppError::Auth("Invalid username or password".to_string()))?;

    // Verify password
    if !verify_password(&payload.password, &password_hash)? {
        return Err(AppError::Auth("Invalid username or password".to_string()));
    }

    // Generate JWT token
    let (token, expires_in) = generate_token(&user_id, &username, &state.config)?;

    Ok(Json(AuthResponse {
        token,
        expires_in,
        user: UserInfo {
            id: user_id,
            username,
            email,
        },
    }))
}
