//! User profile handlers

use axum::{
    extract::State,
    Extension,
    Json,
};

use crate::error::{AppError, AppResult};
use crate::models::{AppState, Claims, UserInfo};

/// Get current user profile
pub async fn get_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> AppResult<Json<UserInfo>> {
    let user: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, username, email FROM users WHERE id = ?"
    )
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Database(e))?;

    let (id, username, email) = user
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(UserInfo { id, username, email }))
}
