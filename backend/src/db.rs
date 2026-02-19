//! Database operations and migrations

use anyhow::Result;
use sqlx::SqlitePool;

pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    // Create users table with failed login tracking
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            failed_login_attempts INTEGER DEFAULT 0,
            last_failed_login_at TEXT,
            locked_until TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    
    // Add failed_login_attempts column if it doesn't exist (migration for existing databases)
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0"
    )
    .execute(pool)
    .await;
    
    // Add last_failed_login_at column if it doesn't exist
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN last_failed_login_at TEXT"
    )
    .execute(pool)
    .await;
    
    // Add locked_until column if it doesn't exist
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN locked_until TEXT"
    )
    .execute(pool)
    .await;

    // Create messages table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            seed_hash TEXT NOT NULL,
            original_filename TEXT,
            stegano_image_path TEXT,
            metadata_overflow TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create captcha_sessions table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS captcha_sessions (
            id TEXT PRIMARY KEY,
            answer TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_captcha_expires ON captcha_sessions(expires_at)")
        .execute(pool)
        .await?;

    // Clean up expired captcha sessions
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("DELETE FROM captcha_sessions WHERE expires_at < ?")
        .bind(&now)
        .execute(pool)
        .await?;

    // Create rate_limit table for tracking registration attempts
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rate_limits (
            id TEXT PRIMARY KEY,
            ip_address TEXT NOT NULL,
            attempt_count INTEGER NOT NULL DEFAULT 1,
            first_attempt_at TEXT NOT NULL,
            last_attempt_at TEXT NOT NULL,
            locked_until TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for rate limits
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip_address)")
        .execute(pool)
        .await?;

    // Clean up old rate limits (older than 1 hour)
    let cleanup_time = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    sqlx::query("DELETE FROM rate_limits WHERE last_attempt_at < ?")
        .bind(&cleanup_time)
        .execute(pool)
        .await?;

    // Add failed_login_attempts and locked_until columns to users if they don't exist
    // This is handled via migration logic - in production use proper migrations

    Ok(())
}
