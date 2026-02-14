//! Local captcha implementation for brute force prevention

use base64::{engine::general_purpose::STANDARD, Engine};
use captcha::Captcha;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::CaptchaSession;

/// Generate a new captcha challenge
#[allow(dead_code)]
pub fn generate_captcha(difficulty: usize) -> AppResult<CaptchaSession> {
    let mut captcha = Captcha::new();
    
    // Add random characters based on difficulty
    for _ in 0..difficulty {
        captcha.add_char();
    }
    
    // Apply view settings
    let captcha = captcha.view(220, 120);
    
    let answer = captcha.chars_as_string();
    
    let now = Utc::now();
    let expires_at = now + Duration::minutes(5); // Captcha expires in 5 minutes
    
    Ok(CaptchaSession {
        id: Uuid::new_v4().to_string(),
        answer,
        created_at: now,
        expires_at,
    })
}

/// Generate captcha and return base64 image
pub fn generate_captcha_image(difficulty: usize) -> AppResult<(String, String, String)> {
    let mut captcha = Captcha::new();
    
    // Add random characters based on difficulty
    for _ in 0..difficulty {
        captcha.add_char();
    }
    
    // Apply view settings
    let captcha = captcha.view(220, 120);
    
    let answer = captcha.chars_as_string();
    let id = Uuid::new_v4().to_string();
    
    // Get PNG data - captcha.as_png() returns Option<Vec<u8>>
    let png_data = captcha.as_png()
        .ok_or_else(|| AppError::Captcha("Failed to convert captcha to PNG".to_string()))?;
    
    let image_base64 = STANDARD.encode(&png_data);
    
    Ok((id, answer, image_base64))
}

/// Verify captcha answer
pub fn verify_captcha(answer: &str, expected: &str) -> AppResult<bool> {
    // Case-insensitive comparison
    let answer_clean: String = answer.chars().filter(|c| c.is_alphanumeric()).collect();
    let expected_clean: String = expected.chars().filter(|c| c.is_alphanumeric()).collect();
    
    Ok(answer_clean.to_lowercase() == expected_clean.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_captcha() {
        assert!(verify_captcha("ABC123", "abc123").unwrap());
        assert!(verify_captcha("A B C 1 2 3", "abc123").unwrap());
        assert!(!verify_captcha("wrong", "abc123").unwrap());
    }
}
