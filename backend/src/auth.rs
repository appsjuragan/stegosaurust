//! Authentication and JWT handling

use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::models::{AppState, Claims};

/// Generate a JWT token for a user
pub fn generate_token(user_id: &str, username: &str, config: &Config) -> AppResult<(String, i64)> {
    let now = Utc::now();
    let exp = now + Duration::seconds(config.jwt_expiration);
    
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Auth(format!("Token generation failed: {}", e)))?;

    Ok((token, config.jwt_expiration))
}

/// Validate a JWT token and return claims
pub fn validate_token(token: &str, config: &Config) -> AppResult<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|e| AppError::Auth(format!("Invalid token: {}", e)))?;

    Ok(token_data.claims)
}

/// Extract token from Authorization header
pub fn extract_token(req: &Request) -> AppResult<String> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Auth(
            "Invalid authorization header format".to_string(),
        ));
    }

    Ok(auth_header[7..].to_string())
}

/// JWT authentication middleware
pub async fn jwt_auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> AppResult<Response> {
    let token = extract_token(&req)?;
    let claims = validate_token(&token, &state.config)?;

    // Verify user still exists in database
    let user_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)")
        .bind(&claims.sub)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);

    if !user_exists {
        return Err(AppError::Auth("User not found".to_string()));
    }

    // Add claims to request extensions
    let mut req = req;
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

/// Hash password using Argon2
pub fn hash_password(password: &str) -> AppResult<String> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Auth(format!("Password hashing failed: {}", e)))?
        .to_string();

    Ok(hash)
}

/// Verify password against hash
pub fn verify_password(password: &str, hash: &str) -> AppResult<bool> {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };

    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AppError::Auth(format!("Invalid hash format: {}", e)))?;

    let result = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map(|_| true)
        .unwrap_or(false);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }
}
