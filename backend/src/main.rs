//! Secure Steganography Backend
//! 
//! A Rust backend for encrypted text storage with steganography support
//! Features: JWT auth, captcha, input sanitization, stegano for PNG/JPG/WEBP

mod auth;
mod captcha;
mod config;
mod crypto;
mod db;
mod error;
mod handlers;
mod models;
mod stegano;

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file
    dotenvy::dotenv().ok();

    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Stegosaurust Backend v0.1.0-beta");
    tracing::info!("Configuration loaded");
    tracing::info!("Server will bind to {}:{}", config.server_host, config.server_port);
    tracing::info!("Data directory: {}", config.data_dir);
    tracing::info!("CORS origin: {}", config.cors_origin);

    // Initialize database
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| format!("sqlite:{}/stegano.db?mode=rwc", config.data_dir));
    
    // Ensure data directories exist
    std::fs::create_dir_all(&config.data_dir)?;
    std::fs::create_dir_all(format!("{}/uploads", config.data_dir))?;
    std::fs::create_dir_all(format!("{}/output", config.data_dir))?;
    
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;
    
    // Run migrations
    db::run_migrations(&pool).await?;
    tracing::info!("Database initialized");

    // Initialize MinIO / S3
    let credentials = s3::creds::Credentials::new(
        Some(&config.minio_access_key),
        Some(&config.minio_secret_key),
        None,
        None,
        None,
    )?;

    let region = s3::Region::Custom {
        region: "us-east-1".to_string(), // Default for MinIO
        endpoint: config.minio_endpoint.clone(),
    };

    let bucket_box = s3::Bucket::new(
        &config.minio_bucket,
        region.clone(),
        credentials.clone(),
    )?;
    
    // Unbox immediately and force path style for MinIO
    let bucket = *bucket_box;
    let bucket = bucket.with_path_style();

    // Ensure bucket exists
    if !bucket.exists().await? {
        // Create bucket using associated function with path style
        s3::Bucket::create_with_path_style(
            &config.minio_bucket,
            region,
            credentials,
            s3::BucketConfiguration::default(),
        ).await?; 
        tracing::info!("Created bucket: {}", config.minio_bucket);
    }

    // Create shared state
    let state = models::AppState {
        pool: pool.clone(),
        config: config.clone(),
        storage: *bucket,
    };

    // Build CORS layer from config
    let cors = if config.cors_origin == "*" {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let origin = config.cors_origin.parse::<axum::http::HeaderValue>()
            .expect("Invalid CORS_ORIGIN value");
        CorsLayer::new()
            .allow_origin(origin)
            .allow_methods(Any)
            .allow_headers(Any)
    };

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/register", post(handlers::auth::register))
        .route("/login", post(handlers::auth::login))
        .route("/captcha", get(handlers::captcha::get_captcha))
        .route("/captcha/verify", post(handlers::captcha::verify_captcha_endpoint));

    // Protected routes (JWT auth required)
    let protected_routes = Router::new()
        .route("/encrypt", post(handlers::crypto::encrypt_text_handler))
        .route("/decrypt", post(handlers::crypto::decrypt_text_handler))
        .route("/stegano/embed", post(handlers::stegano::embed_message_handler))
        .route("/stegano/extract", post(handlers::stegano::extract_message_handler))
        .route("/stegano/detect", post(handlers::stegano::detect_stegano_handler))
        .route("/qrcode/generate", post(handlers::qrcode::generate_qr_handler))
        .route("/messages", get(handlers::messages::list_messages))
        .route("/messages/{id}", get(handlers::messages::get_message))
        .route("/messages/{id}", delete(handlers::messages::delete_message))
        .route("/messages/{id}/image", get(handlers::messages::get_message_image))
        .route("/messages/{id}/decrypt", post(handlers::messages::decrypt_message))
        .route("/user/profile", get(handlers::user::get_profile))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::jwt_auth_middleware));

    // Merge into /api namespace
    let api_routes = Router::new()
        .merge(public_routes)
        .merge(protected_routes);

    // Build main router
    let app = Router::new()
        .nest("/api", api_routes)
        .route("/health", get(health_check))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(config.max_upload_size))
        .with_state(state);

    // Start server
    let addr: SocketAddr = format!("{}:{}", config.server_host, config.server_port)
        .parse()
        .expect("Invalid SERVER_HOST or SERVER_PORT");
    tracing::info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

