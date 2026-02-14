//! Encryption module with seed words/passphrase support

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};

use crate::error::{AppError, AppResult};

/// Derive a 256-bit key from seed words using SHA-512 and SHA-256
pub fn derive_key_from_seed(seed_words: &str) -> [u8; 32] {
    // Normalize seed words (lowercase, trim whitespace)
    let normalized = seed_words.to_lowercase().trim().to_string();
    
    // First hash with SHA-512
    let mut hasher = Sha512::new();
    hasher.update(normalized.as_bytes());
    let hash1 = hasher.finalize();
    
    // Second hash with SHA-256 for key derivation
    let mut hasher = Sha256::new();
    hasher.update(&hash1);
    hasher.update(b"stegano-encryption-key-v1"); // Salt
    let key = hasher.finalize();
    
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key);
    key_array
}

/// Generate hash of seed words for storage verification
pub fn hash_seed_words(seed_words: &str) -> String {
    let normalized = seed_words.to_lowercase().trim().to_string();
    
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hasher.update(b"seed-verification-v1");
    
    STANDARD.encode(hasher.finalize())
}

/// Encrypt text using AES-256-GCM with seed words as key
pub fn encrypt_text(plaintext: &str, seed_words: &str) -> AppResult<String> {
    if plaintext.is_empty() {
        return Err(AppError::Encryption("Plaintext cannot be empty".to_string()));
    }
    
    if seed_words.trim().is_empty() {
        return Err(AppError::Encryption("Seed words cannot be empty".to_string()));
    }
    
    // Derive key from seed words
    let key = derive_key_from_seed(seed_words);
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| AppError::Encryption(format!("Failed to create cipher: {}", e)))?;
    
    // Generate random 96-bit nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| AppError::Encryption(format!("Encryption failed: {}", e)))?;
    
    // Combine nonce + ciphertext and encode as base64
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);
    
    Ok(STANDARD.encode(&combined))
}

/// Decrypt text using AES-256-GCM with seed words as key
pub fn decrypt_text(encrypted: &str, seed_words: &str) -> AppResult<String> {
    if encrypted.is_empty() {
        return Err(AppError::Encryption("Encrypted data cannot be empty".to_string()));
    }
    
    if seed_words.trim().is_empty() {
        return Err(AppError::Encryption("Seed words cannot be empty".to_string()));
    }
    
    // Decode base64
    let combined = STANDARD
        .decode(encrypted)
        .map_err(|e| AppError::Encryption(format!("Invalid base64 encoding: {}", e)))?;
    
    if combined.len() < 12 {
        return Err(AppError::Encryption("Invalid encrypted data length".to_string()));
    }
    
    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Derive key from seed words
    let key = derive_key_from_seed(seed_words);
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| AppError::Encryption(format!("Failed to create cipher: {}", e)))?;
    
    // Decrypt the ciphertext
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AppError::Encryption(format!("Decryption failed: {}", e)))?;
    
    String::from_utf8(plaintext)
        .map_err(|e| AppError::Encryption(format!("Invalid UTF-8 in plaintext: {}", e)))
}

/// Verify seed words match a stored hash
#[allow(dead_code)]
pub fn verify_seed_hash(seed_words: &str, stored_hash: &str) -> AppResult<bool> {
    let computed_hash = hash_seed_words(seed_words);
    Ok(computed_hash == stored_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = "Hello, World! This is a secret message.";
        let seed = "my secret seed words phrase";
        
        let encrypted = encrypt_text(plaintext, seed).unwrap();
        let decrypted = decrypt_text(&encrypted, seed).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn test_wrong_seed_fails() {
        let plaintext = "Secret message";
        let seed = "correct seed";
        
        let encrypted = encrypt_text(plaintext, seed).unwrap();
        let result = decrypt_text(&encrypted, "wrong seed");
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_seed_normalization() {
        // Test that seed words are normalized (case insensitive, whitespace trimmed)
        let plaintext = "Test message";
        let encrypted = encrypt_text(plaintext, "  My Seed Words  ").unwrap();
        let decrypted = decrypt_text(&encrypted, "my seed words").unwrap();
        
        assert_eq!(plaintext, decrypted);
    }
}
