# SteganoVault Backend

A Rust backend for secure steganography application with AES-256 encryption and LSB steganography support.

## Features

- **AES-256-GCM Encryption**: Military-grade encryption using seed words as keys
- **LSB Steganography**: Hide encrypted data in PNG, JPG, and WebP images
- **Metadata Overflow**: Automatically handles large messages by storing overflow in image metadata
- **QR Code Generation**: Generate QR codes for seed word transmission
- **JWT Authentication**: Secure token-based authentication
- **Local Captcha**: Built-in captcha system to prevent brute force attacks
- **Input Sanitization**: All inputs are sanitized and validated

## Tech Stack

- **Framework**: Axum 0.7
- **ORM**: SQLx with SQLite
- **Encryption**: AES-256-GCM, SHA-256/SHA-512
- **Password Hashing**: Argon2
- **JWT**: jsonwebtoken
- **Image Processing**: image crate
- **QR Code**: qrcode crate

## Prerequisites

- Rust 1.70+
- Cargo

## Running the Backend

```bash
# Navigate to backend directory
cd backend

# Build the project
cargo build --release

# Run the server
cargo run --release
```

The server will start on `http://localhost:8080`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:./data/stegano.db?mode=rwc` | SQLite database path |
| `JWT_SECRET` | `super-secret-key-change-in-production` | JWT signing secret |
| `JWT_EXPIRATION` | `86400` | Token expiration in seconds |
| `CAPTCHA_DIFFICULTY` | `5` | Number of captcha characters |
| `MAX_UPLOAD_SIZE` | `10485760` | Max upload size in bytes (10MB) |
| `RUST_LOG` | `info` | Log level |

## API Endpoints

### Public Endpoints

- `GET /health` - Health check
- `GET /api/captcha` - Get captcha image
- `POST /api/captcha/verify` - Verify captcha answer
- `POST /api/register` - Register new user
- `POST /api/login` - Login user

### Protected Endpoints (Requires JWT)

- `POST /api/encrypt` - Encrypt text with seed words
- `POST /api/decrypt` - Decrypt text with seed words
- `POST /api/stegano/embed` - Embed message in image
- `POST /api/stegano/extract` - Extract message from image
- `POST /api/qrcode/generate` - Generate QR code
- `POST /api/qrcode/scan` - Scan QR code
- `GET /api/messages` - List user's messages
- `GET /api/messages/{id}` - Get specific message
- `DELETE /api/messages/{id}` - Delete message
- `GET /api/user/profile` - Get user profile

## Request/Response Examples

### Register
```json
POST /api/register
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "securepassword123",
  "captcha_id": "uuid",
  "captcha_answer": "ABC12"
}

Response:
{
  "token": "jwt_token",
  "expires_in": 86400,
  "user": {
    "id": "uuid",
    "username": "testuser",
    "email": "test@example.com"
  }
}
```

### Encrypt
```json
POST /api/encrypt
Authorization: Bearer <token>
{
  "text": "Secret message",
  "seed_words": "my secret passphrase"
}

Response:
{
  "encrypted_data": "base64_encrypted_data",
  "seed_hash": "hash_of_seed_words"
}
```

### Steganography Embed
```
POST /api/stegano/embed
Authorization: Bearer <token>
Content-Type: multipart/form-data

image: <image file>
format: png
message: Secret message to hide
seed_words: encryption passphrase
```

## Steganography Details

### LSB (Least Significant Bit)
- Uses 2 bits per color channel (R, G, B)
- Capacity: approximately 0.75 bytes per pixel
- Magic marker "STGN" for validation
- 8-byte length prefix for message size

### Metadata Overflow
When the message exceeds LSB capacity:
1. Message is split between LSB and metadata
2. Overflow stored in:
   - PNG: tEXt chunk
   - JPEG: COM marker
   - WebP: Custom header

## Security Considerations

1. **Password Storage**: Argon2 with random salt
2. **JWT**: HS256 algorithm with configurable expiration
3. **Captcha**: Prevents automated brute force attacks
4. **Input Sanitization**: All user inputs are sanitized
5. **CORS**: Configurable cross-origin settings

## Building for Production

```bash
# Build optimized release binary
cargo build --release

# The binary will be at target/release/stegano-backend
```

## Database Schema

### Users
```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

### Messages
```sql
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    encrypted_data TEXT NOT NULL,
    seed_hash TEXT NOT NULL,
    original_filename TEXT,
    stegano_image_path TEXT,
    metadata_overflow TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Captcha Sessions
```sql
CREATE TABLE captcha_sessions (
    id TEXT PRIMARY KEY,
    answer TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
```

## License

MIT

Built by Appsjuragan
