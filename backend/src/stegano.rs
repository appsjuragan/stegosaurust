//! Steganography implementation for PNG, JPG, and WEBP
//! 
//! Supports LSB (Least Significant Bit) embedding for PNG/WebP
//! And metadata embedding for JPG with overflow support

use base64::Engine;
use image::{DynamicImage, GenericImageView, ImageBuffer, ImageFormat, Rgba};
use std::io::Cursor;

use crate::crypto::{decrypt_text, encrypt_text};
use crate::error::{AppError, AppResult};

/// Maximum bytes that can be embedded in an image using LSB
/// Approximation: (width * height * 3) / 8 bytes available
/// Using 2 bits per channel for better capacity while maintaining quality

/// Embed message into image using steganography
/// Returns: (modified_image_base64, metadata_used, overflow_size)
pub fn embed_message(
    image_data: &[u8],
    message: &str,
    seed_words: &str,
    format: &str,
) -> AppResult<(String, bool, usize)> {
    // First encrypt the message
    let encrypted = encrypt_text(message, seed_words)?;
    
    // Load the image with auto-detection but use target format for logic
    let img_format = parse_image_format(format)?;
    let img = image::load_from_memory(image_data)
        .map_err(|e| AppError::Stegano(format!("Failed to load image: {}", e)))?;
    
    let (width, height) = img.dimensions();
    
    // Only use LSB for PNG as it's lossless. 
    // JPG/WebP compression destroys LSB data, so we force overflow to metadata.
    let max_capacity = if img_format == ImageFormat::Png {
        calculate_capacity(width, height)
    } else {
        0
    };
    
    // Prepare message with length prefix and magic marker
    let message_bytes = prepare_message_bytes(&encrypted)?;
    let message_size = message_bytes.len();
    
    // Check if message fits in LSB
    if message_size <= max_capacity {
        // Embed using LSB
        let stego_img = embed_lsb(&img, &message_bytes)?;
        let encoded = encode_image_to_base64(&stego_img, img_format)?;
        Ok((encoded, false, 0))
    } else {
        // Split message between LSB and metadata
        let lsb_data = &message_bytes[..max_capacity];
        let overflow_data = &message_bytes[max_capacity..];
        
        // Embed what fits in LSB
        let stego_img = embed_lsb(&img, lsb_data)?;
        
        // Store overflow in metadata
        let overflow_base64 = base64::engine::general_purpose::STANDARD.encode(overflow_data);
        let overflow_json = serde_json::json!({
            "overflow": overflow_base64,
            "total_size": message_size,
            "lsb_size": max_capacity,
        });
        
        // Embed metadata based on format
        let encoded = embed_metadata(&stego_img, &overflow_json.to_string(), img_format)?;
        
        Ok((encoded, true, overflow_data.len()))
    }
}

/// Extract message from steganographic image
pub fn extract_message(
    image_data: &[u8],
    seed_words: &str,
    format: &str,
) -> AppResult<String> {
    let img_format = parse_image_format(format)?;
    let img = image::load_from_memory(image_data)
        .map_err(|e| AppError::Stegano(format!("Failed to load image: {}", e)))?;
    
    // Extract LSB data
    let lsb_bytes = extract_lsb(&img)?;
    
    // Check for metadata overflow
    let metadata = extract_metadata(image_data, img_format)?;
    
    let encrypted = if let Some(ref metadata_str) = metadata {
        // Parse overflow data
        let overflow_data: serde_json::Value = serde_json::from_str(metadata_str)
            .map_err(|e| AppError::Stegano(format!("Invalid metadata format: {}", e)))?;
        
        let overflow_base64 = overflow_data["overflow"]
            .as_str()
            .ok_or_else(|| AppError::Stegano("Missing overflow data".to_string()))?;
        
        let total_size = overflow_data["total_size"]
            .as_u64()
            .ok_or_else(|| AppError::Stegano("Missing total size".to_string()))? as usize;
        
        let lsb_size = overflow_data["lsb_size"]
            .as_u64()
            .ok_or_else(|| AppError::Stegano("Missing LSB size".to_string()))? as usize;
        
        // Combine LSB and overflow data
        let overflow_bytes = base64::engine::general_purpose::STANDARD
            .decode(overflow_base64)
            .map_err(|e| AppError::Stegano(format!("Invalid overflow encoding: {}", e)))?;
        
        let mut combined = Vec::with_capacity(total_size);
        combined.extend_from_slice(&lsb_bytes[..lsb_size]);
        combined.extend_from_slice(&overflow_bytes);
        
        decode_message_bytes(&combined)?
    } else {
        // No overflow, all data in LSB
        decode_message_bytes(&lsb_bytes)?
    };
    
    // Decrypt the message
    decrypt_text(&encrypted, seed_words)
}

/// Detect if an image contains steganographic content
pub fn detect_stegano_content(
    image_data: &[u8],
    format: &str,
) -> AppResult<bool> {
    let img_format = parse_image_format(format)?;
    let img = image::load_from_memory(image_data)
        .map_err(|e| AppError::Stegano(format!("Failed to load image: {}", e)))?;
    
    // Check metadata first (primary for JPG/WebP, secondary for PNG)
    if let Ok(Some(metadata_str)) = extract_metadata(image_data, img_format) {
        if let Ok(overflow_data) = serde_json::from_str::<serde_json::Value>(&metadata_str) {
            if let Some(overflow_base64) = overflow_data["overflow"].as_str() {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(overflow_base64) {
                    if bytes.len() >= 4 && &bytes[0..4] == b"STGN" {
                        return Ok(true);
                    }
                }
            }
        }
    }
    
    // Check LSB (primary for PNG)
    if img_format == ImageFormat::Png {
        if let Ok(lsb_bytes) = extract_lsb(&img) {
            if lsb_bytes.len() >= 4 && &lsb_bytes[0..4] == b"STGN" {
                return Ok(true);
            }
        }
    }
    
    Ok(false)
}

/// Calculate LSB capacity for an image (in bytes)
fn calculate_capacity(width: u32, height: u32) -> usize {
    // Using 2 bits per channel (R, G, B) = 6 bits per pixel
    // Header: 8 bytes for magic + 4 bytes for length = 12 bytes overhead
    let raw_capacity = (width * height * 3 / 4) as usize; // 6 bits per pixel = 0.75 bytes per pixel
    raw_capacity.saturating_sub(12)
}

/// Prepare message bytes with magic marker and length prefix
fn prepare_message_bytes(encrypted_message: &str) -> AppResult<Vec<u8>> {
    let msg_bytes = encrypted_message.as_bytes();
    
    // Magic marker: "STGN" (4 bytes)
    let magic = b"STGN";
    
    // Message length as 8-byte big-endian
    let len = (msg_bytes.len() as u64).to_be_bytes();
    
    let mut result = Vec::with_capacity(4 + 8 + msg_bytes.len());
    result.extend_from_slice(magic);
    result.extend_from_slice(&len);
    result.extend_from_slice(msg_bytes);
    
    Ok(result)
}

/// Decode message bytes from raw extracted data
fn decode_message_bytes(raw_bytes: &[u8]) -> AppResult<String> {
    if raw_bytes.len() < 12 {
        return Err(AppError::Stegano("Data too short".to_string()));
    }
    
    // Verify magic marker
    if &raw_bytes[0..4] != b"STGN" {
        return Err(AppError::Stegano("Invalid magic marker - not a steganographic image".to_string()));
    }
    
    // Extract message length
    let len = u64::from_be_bytes([
        raw_bytes[4], raw_bytes[5], raw_bytes[6], raw_bytes[7],
        raw_bytes[8], raw_bytes[9], raw_bytes[10], raw_bytes[11],
    ]) as usize;
    
    if raw_bytes.len() < 12 + len {
        return Err(AppError::Stegano("Incomplete message data".to_string()));
    }
    
    String::from_utf8(raw_bytes[12..12 + len].to_vec())
        .map_err(|e| AppError::Stegano(format!("Invalid UTF-8 in message: {}", e)))
}

/// Embed data using LSB (Least Significant Bit) technique
fn embed_lsb(img: &DynamicImage, data: &[u8]) -> AppResult<DynamicImage> {
    let (width, height) = img.dimensions();
    let rgba_img = img.to_rgba8();
    
    // Convert data to bits (2 bits per data byte -> 4 bits per byte of data)
    let bits = bytes_to_bits_2(data);
    
    let mut new_img: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::new(width, height);
    
    let mut bit_idx = 0;
    for y in 0..height {
        for x in 0..width {
            let pixel = rgba_img.get_pixel(x, y);
            let mut new_pixel = pixel.clone();
            
            // Embed 2 bits in R, G, B channels (skip A)
            for channel in 0..3 {
                if bit_idx < bits.len() {
                    let original = pixel[channel];
                    // Clear lowest 2 bits and set new bits
                    let modified = (original & 0xFC) | bits[bit_idx];
                    new_pixel[channel] = modified;
                    bit_idx += 1;
                }
            }
            
            new_img.put_pixel(x, y, new_pixel);
        }
    }
    
    Ok(DynamicImage::ImageRgba8(new_img))
}

/// Extract data from LSB
fn extract_lsb(img: &DynamicImage) -> AppResult<Vec<u8>> {
    let (width, height) = img.dimensions();
    let rgba_img = img.to_rgba8();
    
    // Extract bits from image
    let mut bits = Vec::with_capacity((width * height * 3) as usize);
    
    for y in 0..height {
        for x in 0..width {
            let pixel = rgba_img.get_pixel(x, y);
            
            // Extract 2 bits from R, G, B channels
            for channel in 0..3 {
                bits.push(pixel[channel] & 0x03);
            }
        }
    }
    
    // Convert bits back to bytes
    Ok(bits_to_bytes_2(&bits))
}

/// Convert bytes to 2-bit values (0-3)
fn bytes_to_bits_2(data: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(data.len() * 4);
    
    for &byte in data {
        bits.push((byte >> 6) & 0x03);
        bits.push((byte >> 4) & 0x03);
        bits.push((byte >> 2) & 0x03);
        bits.push(byte & 0x03);
    }
    
    bits
}

/// Convert 2-bit values back to bytes
fn bits_to_bytes_2(bits: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(bits.len() / 4);
    
    for chunk in bits.chunks(4) {
        if chunk.len() == 4 {
            let byte = (chunk[0] << 6) | (chunk[1] << 4) | (chunk[2] << 2) | chunk[3];
            bytes.push(byte);
        }
    }
    
    bytes
}

/// Parse image format from string
fn parse_image_format(format: &str) -> AppResult<ImageFormat> {
    match format.to_lowercase().as_str() {
        "png" => Ok(ImageFormat::Png),
        "jpg" | "jpeg" => Ok(ImageFormat::Jpeg),
        "webp" => Ok(ImageFormat::WebP),
        _ => Err(AppError::Stegano(format!(
            "Unsupported image format: {}",
            format
        ))),
    }
}

/// Encode image to base64 string
fn encode_image_to_base64(img: &DynamicImage, format: ImageFormat) -> AppResult<String> {
    let mut buffer = Vec::new();
    img.write_to(&mut Cursor::new(&mut buffer), format)
        .map_err(|e| AppError::Stegano(format!("Failed to encode image: {}", e)))?;
    
    Ok(base64::engine::general_purpose::STANDARD.encode(&buffer))
}

/// Embed metadata into image (for overflow data)
fn embed_metadata(img: &DynamicImage, metadata: &str, format: ImageFormat) -> AppResult<String> {
    match format {
        ImageFormat::Png => {
            // For PNG, we can use tEXt chunks (simplified - store in comment)
            // In production, use a proper PNG library to add text chunks
            let mut buffer = Vec::new();
            img.write_to(&mut Cursor::new(&mut buffer), ImageFormat::Png)
                .map_err(|e| AppError::Stegano(format!("Failed to encode PNG: {}", e)))?;
            
            // Insert metadata before IEND chunk
            let metadata_chunk = create_png_text_chunk("stegano_overflow", metadata);
            
            // Find IEND chunk and insert before it
            if let Some(pos) = find_png_iend(&buffer) {
                let mut new_buffer = Vec::with_capacity(buffer.len() + metadata_chunk.len());
                new_buffer.extend_from_slice(&buffer[..pos]);
                new_buffer.extend_from_slice(&metadata_chunk);
                new_buffer.extend_from_slice(&buffer[pos..]);
                
                Ok(base64::engine::general_purpose::STANDARD.encode(&new_buffer))
            } else {
                Ok(base64::engine::general_purpose::STANDARD.encode(&buffer))
            }
        }
        ImageFormat::Jpeg => {
            // For JPEG, embed in COM marker
            let mut buffer = Vec::new();
            img.write_to(&mut Cursor::new(&mut buffer), ImageFormat::Jpeg)
                .map_err(|e| AppError::Stegano(format!("Failed to encode JPEG: {}", e)))?;
            
            // Insert COM marker after SOI
            let com_marker = create_jpeg_com_marker(metadata);
            let mut new_buffer = Vec::with_capacity(buffer.len() + com_marker.len());
            new_buffer.extend_from_slice(&buffer[..2]); // SOI marker
            new_buffer.extend_from_slice(&com_marker);
            new_buffer.extend_from_slice(&buffer[2..]);
            
            Ok(base64::engine::general_purpose::STANDARD.encode(&new_buffer))
        }
        ImageFormat::WebP => {
            // For WebP, we need to use a different approach
            // Store metadata as base64 prefix (simplified)
            let mut buffer = Vec::new();
            img.write_to(&mut Cursor::new(&mut buffer), ImageFormat::WebP)
                .map_err(|e| AppError::Stegano(format!("Failed to encode WebP: {}", e)))?;
            
            // Prepend metadata length and data
            let metadata_bytes = metadata.as_bytes();
            let len = metadata_bytes.len() as u32;
            let mut new_buffer = Vec::with_capacity(4 + metadata_bytes.len() + buffer.len());
            new_buffer.extend_from_slice(&len.to_be_bytes());
            new_buffer.extend_from_slice(metadata_bytes);
            new_buffer.extend_from_slice(&buffer);
            
            Ok(base64::engine::general_purpose::STANDARD.encode(&new_buffer))
        }
        _ => Err(AppError::Stegano("Unsupported format for metadata".to_string())),
    }
}

/// Extract metadata from image
fn extract_metadata(image_data: &[u8], format: ImageFormat) -> AppResult<Option<String>> {
    match format {
        ImageFormat::Png => {
            // Search for our custom tEXt chunk
            extract_png_text_chunk(image_data, "stegano_overflow")
        }
        ImageFormat::Jpeg => {
            // Search for COM marker
            extract_jpeg_com_marker(image_data)
        }
        ImageFormat::WebP => {
            // Our custom format has metadata at the beginning
            if image_data.len() < 4 {
                return Ok(None);
            }
            
            let len = u32::from_be_bytes([
                image_data[0], image_data[1], image_data[2], image_data[3],
            ]) as usize;
            
            if image_data.len() < 4 + len {
                return Ok(None);
            }
            
            let metadata = String::from_utf8(image_data[4..4 + len].to_vec())
                .map_err(|e| AppError::Stegano(format!("Invalid metadata encoding: {}", e)))?;
            
            Ok(Some(metadata))
        }
        _ => Ok(None),
    }
}

/// Create PNG tEXt chunk
fn create_png_text_chunk(key: &str, value: &str) -> Vec<u8> {
    let mut chunk = Vec::new();
    
    // Chunk data: keyword + null + text
    let mut data = key.as_bytes().to_vec();
    data.push(0);
    data.extend_from_slice(value.as_bytes());
    
    // Length (4 bytes, big-endian)
    chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
    
    // Type (4 bytes): "tEXt"
    chunk.extend_from_slice(b"tEXt");
    
    // Data
    chunk.extend_from_slice(&data);
    
    // CRC32 (4 bytes) - simplified, in production use proper CRC
    let crc = crc32fast::hash(&chunk[4..]);
    chunk.extend_from_slice(&crc.to_be_bytes());
    
    chunk
}

/// Find PNG IEND chunk position
fn find_png_iend(data: &[u8]) -> Option<usize> {
    // PNG signature is 8 bytes, then chunks
    if data.len() < 8 {
        return None;
    }
    
    let mut pos = 8;
    while pos + 8 <= data.len() {
        let chunk_len = u32::from_be_bytes([
            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
        ]) as usize;
        
        let chunk_type = &data[pos + 4..pos + 8];
        if chunk_type == b"IEND" {
            return Some(pos);
        }
        
        // Move to next chunk: 4 (len) + 4 (type) + data + 4 (crc)
        pos += 4 + 4 + chunk_len + 4;
    }
    
    None
}

/// Extract PNG tEXt chunk value by key
fn extract_png_text_chunk(data: &[u8], key: &str) -> AppResult<Option<String>> {
    if data.len() < 8 {
        return Ok(None);
    }
    
    let mut pos = 8;
    while pos + 8 <= data.len() {
        let chunk_len = u32::from_be_bytes([
            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
        ]) as usize;
        
        let chunk_type = &data[pos + 4..pos + 8];
        
        if chunk_type == b"tEXt" && pos + 8 + chunk_len <= data.len() {
            let chunk_data = &data[pos + 8..pos + 8 + chunk_len];
            
            // Find null separator
            if let Some(null_pos) = chunk_data.iter().position(|&b| b == 0) {
                let chunk_key = String::from_utf8_lossy(&chunk_data[..null_pos]);
                if chunk_key == key {
                    let value = String::from_utf8_lossy(&chunk_data[null_pos + 1..]);
                    return Ok(Some(value.to_string()));
                }
            }
        }
        
        pos += 4 + 4 + chunk_len + 4;
    }
    
    Ok(None)
}

/// Create JPEG COM marker(s) handling large payloads
fn create_jpeg_com_marker(comment: &str) -> Vec<u8> {
    let comment_bytes = comment.as_bytes();
    // JPEG COM marker max length is 65535 bytes (including 2 length bytes)
    // So max data per marker is 65533 bytes
    const MAX_CHUNK_SIZE: usize = 65533;
    
    let mut result = Vec::with_capacity(comment_bytes.len() + (comment_bytes.len() / MAX_CHUNK_SIZE + 1) * 4);
    
    for chunk in comment_bytes.chunks(MAX_CHUNK_SIZE) {
        // COM marker: 0xFF 0xFE
        result.push(0xFF);
        result.push(0xFE);
        
        // Length (2 bytes, includes length itself)
        let len = (chunk.len() + 2) as u16;
        result.extend_from_slice(&len.to_be_bytes());
        
        // Comment data
        result.extend_from_slice(chunk);
    }
    
    result
}

/// Extract all JPEG COM markers and join them
fn extract_jpeg_com_marker(data: &[u8]) -> AppResult<Option<String>> {
    if data.len() < 4 {
        return Ok(None);
    }
    
    let mut extracted_data = String::new();
    let mut found_any = false;
    
    let mut pos = 2; // Skip SOI marker
    while pos + 4 <= data.len() {
        if data[pos] == 0xFF {
            let marker = data[pos + 1];
            
            if marker == 0xFE {
                // COM marker found
                let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                if pos + 2 + len <= data.len() {
                    let chunk = String::from_utf8_lossy(&data[pos + 4..pos + 2 + len]);
                    extracted_data.push_str(&chunk);
                    found_any = true;
                    
                    // Move past this marker
                    pos += 2 + len;
                    continue;
                }
            } else if marker == 0xDA {
                // SOS marker - start of scan, sometimes metadata follows but usually image data
                // We shouldn't stop scanning completely in case tools put COM after SOS (rare but possible)
                // But standard JPEGs usually put metadata before SOS.
                // For safety, let's break here as navigating scan data without parsing entropy is hard.
                break;
            } else if marker != 0x00 && marker != 0xD9 && marker >= 0xC0 {
                // Skip other valid markers
                // Check if marker has length
                // Markers with no length parameters: RSTn (D0-D7), SOI (D8), EOI (D9), TEM (01)
                if (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01 {
                    pos += 2;
                    continue;
                }
                
                let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                pos += 2 + len;
                continue;
            }
        }
        pos += 1;
    }
    
    if found_any {
        Ok(Some(extracted_data))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits_conversion() {
        let data = b"Hello";
        let bits = bytes_to_bits_2(data);
        let recovered = bits_to_bytes_2(&bits);
        assert_eq!(data.to_vec(), recovered);
    }
}
