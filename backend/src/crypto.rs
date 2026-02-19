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

    #[test]
    fn test_empty_plaintext_fails() {
        let result = encrypt_text("", "seed");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::Encryption(_)));
    }

    #[test]
    fn test_empty_seed_fails() {
        let result = encrypt_text("test", "");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::Encryption(_)));
    }

    #[test]
    fn test_whitespace_only_seed_fails() {
        let result = encrypt_text("test", "   ");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::Encryption(_)));
    }

    #[test]
    fn test_empty_encrypted_fails() {
        let result = decrypt_text("", "seed");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::Encryption(_)));
    }

    #[test]
    fn test_invalid_base64_fails() {
        let result = decrypt_text("not-valid-base64!!!", "seed");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::Encryption(_)));
    }

    #[test]
    fn test_short_encrypted_data_fails() {
        let result = decrypt_text("YWJjZA==", "seed"); // "abcd" in base64, only 4 bytes
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::Encryption(_)));
    }

    #[test]
    fn test_unique_nonce_per_encryption() {
        let plaintext = "Same message";
        let seed = "same seed";
        
        let encrypted1 = encrypt_text(plaintext, seed).unwrap();
        let encrypted2 = encrypt_text(plaintext, seed).unwrap();
        
        // Same plaintext with same seed should produce different ciphertext due to random nonce
        assert_ne!(encrypted1, encrypted2);
        
        // Both should decrypt to the same plaintext
        assert_eq!(plaintext, decrypt_text(&encrypted1, seed).unwrap());
        assert_eq!(plaintext, decrypt_text(&encrypted2, seed).unwrap());
    }

    #[test]
    fn test_unicode_message() {
        let plaintext = "Hello 世界 🌍 Привет мир";
        let seed = "unicode seed";
        
        let encrypted = encrypt_text(plaintext, seed).unwrap();
        let decrypted = decrypt_text(&encrypted, seed).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_long_message() {
        let plaintext = "a".repeat(10000);
        let seed = "long message seed";
        
        let encrypted = encrypt_text(&plaintext, seed).unwrap();
        let decrypted = decrypt_text(&encrypted, seed).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_key_derivation_consistency() {
        let seed = "test seed";
        let key1 = derive_key_from_seed(seed);
        let key2 = derive_key_from_seed(seed);
        
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_key_derivation_normalization() {
        let key1 = derive_key_from_seed("Test Seed");
        let key2 = derive_key_from_seed("  test seed  ");
        
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hash_seed_words() {
        let hash1 = hash_seed_words("test");
        let hash2 = hash_seed_words("TEST");
        
        // Hash should be the same for normalized seeds
        assert_eq!(hash1, hash2);
        
        // Hash should be different for different seeds
        let hash3 = hash_seed_words("different");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_verify_seed_hash() {
        let seed = "my secret seed";
        let hash = hash_seed_words(seed);
        
        assert!(verify_seed_hash(seed, &hash).unwrap());
        assert!(!verify_seed_hash("wrong seed", &hash).unwrap());
    }
}
