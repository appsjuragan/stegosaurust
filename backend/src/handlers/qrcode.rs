//! QR Code handlers for seed words transmission

use axum::{
    extract::State,
    Extension,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use qrcode::QrCode;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::models::{AppState, Claims};

#[derive(Debug, Deserialize)]
pub struct QRCodeRequestJson {
    pub data: String,
    #[serde(default = "default_qr_size")]
    pub size: u32,
}

fn default_qr_size() -> u32 {
    256
}

#[derive(Debug, Serialize)]
pub struct QRCodeResponseJson {
    pub qr_image: String, // Base64 encoded PNG
    pub data: String,
    pub size: u32,
}

/// Generate QR code from data (seed words)
pub async fn generate_qr_handler(
    State(_state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Json(payload): Json<QRCodeRequestJson>,
) -> AppResult<Json<QRCodeResponseJson>> {
    // Validate input
    if payload.data.is_empty() {
        return Err(AppError::Validation("Data cannot be empty".to_string()));
    }

    if payload.data.len() > 1000 {
        return Err(AppError::Validation(
            "Data too long for QR code (max 1000 chars)".to_string(),
        ));
    }

    // Generate QR code
    let code = QrCode::new(payload.data.as_bytes())
        .map_err(|e| AppError::Validation(format!("Failed to generate QR code: {}", e)))?;

    // Convert to PNG
    let image = code.render::<image::Luma<u8>>().build();

    // Resize if needed
    let resized = image::imageops::resize(
        &image,
        payload.size,
        payload.size,
        image::imageops::FilterType::Nearest,
    );

    // Encode to PNG and base64
    let mut buffer = Vec::new();
    let dynamic_image = image::DynamicImage::ImageLuma8(resized);
    dynamic_image
        .write_to(&mut std::io::Cursor::new(&mut buffer), image::ImageFormat::Png)
        .map_err(|e| AppError::Validation(format!("Failed to encode QR: {}", e)))?;

    let qr_base64 = STANDARD.encode(&buffer);

    Ok(Json(QRCodeResponseJson {
        qr_image: qr_base64,
        data: payload.data,
        size: payload.size,
    }))
}

