//! Database operations and migrations

use anyhow::Result;
use sqlx::SqlitePool;

pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    // Create users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

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

    Ok(())
}
