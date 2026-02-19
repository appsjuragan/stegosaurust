//! Authentication handlers

use axum::{
    extract::State,
    Json,
};
use chrono::{Duration, Utc};
use uuid::Uuid;
use validator::Validate;
use std::net::SocketAddr;

use crate::auth::{generate_token, hash_password, verify_password};
use crate::captcha::verify_captcha;
use crate::error::{AppError, AppResult};
use crate::models::{
    AppState, AuthResponse, LoginRequest, RegisterRequest, UserInfo,
};

// Rate limiting constants
const MAX_REGISTRATION_ATTEMPTS_PER_IP: i32 = 5;
const REGISTRATION_WINDOW_MINUTES: i64 = 60;
const MAX_FAILED_LOGIN_ATTEMPTS: i32 = 5;
const LOCKOUT_DURATION_MINUTES: i64 = 15;

/// Extract client IP from request
fn get_client_ip(req: &axum::extract::Request) -> Option<String> {
    // Check X-Forwarded-For header first (for reverse proxy)
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            return Some(forwarded_str.split(',').next().unwrap_or("unknown").trim().to_string());
        }
    }
    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }
    // Fall back to socket address
    if let Some(remote_addr) = req.extensions().get::<SocketAddr>() {
        return Some(remote_addr.ip().to_string());
    }
    None
}

/// Check and update rate limit for registration
async fn check_registration_rate_limit(
    pool: &sqlx::SqlitePool,
    ip_address: &str,
) -> AppResult<()> {
    let now = Utc::now();
    let window_start = (now - Duration::minutes(REGISTRATION_WINDOW_MINUTES)).to_rfc3339();
    let now_str = now.to_rfc3339();

    // Check existing rate limit record
    let existing: Option<(String, i32, String, Option<String>)> = sqlx::query_as(
        "SELECT id, attempt_count, last_attempt_at, locked_until FROM rate_limits WHERE ip_address = ? AND last_attempt_at > ?"
    )
    .bind(ip_address)
    .bind(&window_start)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    if let Some((id, attempt_count, _last_attempt, locked_until)) = existing {
        // Check if currently locked
        if let Some(lock_until) = locked_until {
            if Utc::now().to_rfc3339() < lock_until {
                return Err(AppError::RateLimit(
                    format!("Too many registration attempts. Try again after {}", lock_until)
                ));
            }
        }

        // Check if limit exceeded
        if attempt_count >= MAX_REGISTRATION_ATTEMPTS_PER_IP {
            // Lock the IP
            let lock_until = (Utc::now() + Duration::minutes(LOCKOUT_DURATION_MINUTES)).to_rfc3339();
            sqlx::query("UPDATE rate_limits SET locked_until = ? WHERE id = ?")
                .bind(&lock_until)
                .bind(&id)
                .execute(pool)
                .await
                .map_err(|e| AppError::Database(e))?;

            return Err(AppError::RateLimit(
                format!("Too many registration attempts. Please try again in {} minutes.", LOCKOUT_DURATION_MINUTES)
            ));
        }

        // Increment attempt count
        sqlx::query("UPDATE rate_limits SET attempt_count = attempt_count + 1, last_attempt_at = ? WHERE id = ?")
            .bind(&now_str)
            .bind(&id)
            .execute(pool)
            .await
            .map_err(|e| AppError::Database(e))?;
    } else {
        // Create new rate limit record
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO rate_limits (id, ip_address, attempt_count, first_attempt_at, last_attempt_at) VALUES (?, ?, 1, ?, ?)"
        )
        .bind(&id)
        .bind(ip_address)
        .bind(&now_str)
        .bind(&now_str)
        .execute(pool)
        .await
        .map_err(|e| AppError::Database(e))?;
    }

    Ok(())
}

/// Check if account is locked and record failed login attempt
async fn check_account_lockout(
    pool: &sqlx::SqlitePool,
    username: &str,
) -> AppResult<Option<(String, String)>> {
    let now = Utc::now().to_rfc3339();

    // Check if user exists and is locked
    let user: Option<(String, String, i32, Option<String>)> = sqlx::query_as(
        "SELECT id, username, failed_login_attempts, locked_until FROM users WHERE username = ?"
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    if let Some((id, _username, failed_attempts, locked_until)) = user {
        // Check if account is locked
        if let Some(ref lock_until) = locked_until {
            if now < *lock_until {
                // Calculate remaining lockout time
                let lock_time = chrono::DateTime::parse_from_rfc3339(lock_until)
                    .map_err(|e| AppError::Database(sqlx::Error::Protocol(e.to_string())))?;
                let lock_time_utc: chrono::DateTime<Utc> = lock_time.with_timezone(&Utc);
                let remaining = (lock_time_utc - Utc::now()).num_minutes();
                return Err(AppError::AccountLocked(
                    format!("Account is locked due to too many failed login attempts. Try again in {} minutes.", remaining.max(1))
                ));
            }
        }

        // Check if we should lock the account
        if failed_attempts >= MAX_FAILED_LOGIN_ATTEMPTS {
            let lock_until = (Utc::now() + Duration::minutes(LOCKOUT_DURATION_MINUTES)).to_rfc3339();
            sqlx::query("UPDATE users SET locked_until = ? WHERE id = ?")
                .bind(&lock_until)
                .bind(&id)
                .execute(pool)
                .await
                .map_err(|e| AppError::Database(e))?;

            return Err(AppError::AccountLocked(
                format!("Account is now locked due to too many failed login attempts. Try again in {} minutes.", LOCKOUT_DURATION_MINUTES)
            ));
        }

        return Ok(Some((id, locked_until.unwrap_or_default())));
    }

    Ok(None)
}

/// Record failed login attempt
async fn record_failed_login(
    pool: &sqlx::SqlitePool,
    user_id: &str,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login_at = ? WHERE id = ?"
    )
    .bind(Utc::now().to_rfc3339())
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    Ok(())
}

/// Reset failed login attempts on successful login
async fn reset_failed_login_attempts(
    pool: &sqlx::SqlitePool,
    user_id: &str,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?"
    )
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    Ok(())
}

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

    // Check rate limit (using a placeholder IP since we don't have access to request)
    // In production, use middleware or extract IP from request
    let client_ip = "unknown"; // Placeholder - should be extracted from request
    check_registration_rate_limit(&state.pool, client_ip).await?;

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

    // Check account lockout before proceeding
    let lockout_info = check_account_lockout(&state.pool, &username).await?;

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
        // Record failed login attempt
        if let Some((uid, _)) = lockout_info {
            let _ = record_failed_login(&state.pool, &uid).await;
        }
        return Err(AppError::Auth("Invalid username or password".to_string()));
    }

    // Reset failed login attempts on successful login
    reset_failed_login_attempts(&state.pool, &user_id).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_constants() {
        assert_eq!(MAX_REGISTRATION_ATTEMPTS_PER_IP, 5);
        assert_eq!(REGISTRATION_WINDOW_MINUTES, 60);
        assert_eq!(MAX_FAILED_LOGIN_ATTEMPTS, 5);
        assert_eq!(LOCKOUT_DURATION_MINUTES, 15);
    }

    #[test]
    fn test_get_client_ip_from_forwarded_header() {
        use axum::extract::Request;
        use axum::http::{HeaderMap, HeaderValue};
        
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1, 10.0.0.1"));
        
        let req = Request::builder()
            .headers(headers)
            .body(axum::body::Body::empty())
            .unwrap();
        
        let ip = get_client_ip(&req);
        assert_eq!(ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_get_client_ip_from_real_ip() {
        use axum::extract::Request;
        use axum::http::{HeaderMap, HeaderValue};
        
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("10.0.0.2"));
        
        let req = Request::builder()
            .headers(headers)
            .body(axum::body::Body::empty())
            .unwrap();
        
        let ip = get_client_ip(&req);
        assert_eq!(ip, Some("10.0.0.2".to_string()));
    }

    #[test]
    fn test_get_client_ip_no_headers() {
        use axum::extract::Request;
        use axum::http::HeaderMap;
        
        let headers = HeaderMap::new();
        let req = Request::builder()
            .headers(headers)
            .body(axum::body::Body::empty())
            .unwrap();
        
        let ip = get_client_ip(&req);
        // Without socket address extension, should return None
        assert_eq!(ip, None);
    }

    #[test]
    fn test_sanitize_username() {
        let input = "test\x00user\x1fname";
        let sanitized = crate::models::sanitize_input(input);
        assert_eq!(sanitized, "testusername");
    }

    #[test]
    fn test_sanitize_length_limit() {
        let long_input = "a".repeat(15000);
        let sanitized = crate::models::sanitize_input(&long_input);
        assert_eq!(sanitized.len(), 10000);
    }

    #[test]
    fn test_sanitize_preserves_newlines() {
        let input = "line1\nline2\ttab";
        let sanitized = crate::models::sanitize_input(input);
        assert_eq!(sanitized, "line1\nline2\ttab");
    }

    #[test]
    fn test_sanitize_filename() {
        let input = "../../../etc/passwd";
        let sanitized = crate::models::sanitize_filename(input);
        assert_eq!(sanitized, "etcpasswd");
    }

    #[test]
    fn test_sanitize_filename_preserves_extension() {
        let input = "test.file.png";
        let sanitized = crate::models::sanitize_filename(input);
        assert_eq!(sanitized, "test.file.png");
    }
}
