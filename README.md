# Stegosaurust - Secure Steganography Platform

![Version](https://img.shields.io/badge/version-0.1.0--beta-blue.svg)

**Stegosaurust** (a Rust-based stegano) is a high-performance web application built by **Appsjuragan** for secure message encryption and steganography. It allows users to hide encrypted messages within images (PNG, JPG, WEBP) using advanced steganography techniques.

## Features

-   **Secure Encryption**: Encrypts text using AES-GCM with seed words.
-   **Steganography**: Hides encrypted data within image files.
-   **History Tracking**: innovative history management for encrypted messages.
-   **MinIO Storage**: Scalable storage for steganography images using MinIO/S3.
-   **QR Code**: Generate QR codes for easy sharing.
-   **User Authentication**: Secure JWT-based authentication with Captcha protection.

## Technology Stack

-   **Backend**: Rust (Axum, SQLx, Tokio, Rust-S3)
-   **Frontend**: Next.js (React, TypeScript, TailwindCSS)
-   **Database**: SQLite (Metadata), MinIO (Object Storage)

## Prerequisites

-   Rust (latest stable)
-   Node.js & Bun (or npm)
-   MinIO Server (running locally or remote)

## Getting Started

### Backend Setup

1.  Navigate to `backend` directory:
    ```bash
    cd backend
    ```
2.  Create `.env` file:
    ```ini
    JWT_SECRET=your_jwt_secret
    MINIO_ENDPOINT=http://127.0.0.1:9200
    MINIO_ACCESS_KEY=your_access_key
    MINIO_SECRET_KEY=your_secret_key
    MINIO_BUCKET=stegano
    DATABASE_URL=sqlite:./data/stegano.db?mode=rwc
    ```
3.  Run the server:
    ```bash
    cargo run
    ```
    The server will start on `http://0.0.0.0:8080`.

### Frontend Setup

1.  Navigate to root directory:
    ```bash
    cd ..
    ```
2.  Install dependencies:
    ```bash
    bun install
    ```
3.  Run development server:
    ```bash
    bun run dev
    ```
    The app will utilize port 3000 or 3001.

## Deployment

### Docker / Podman

You can build and deploy the entire application using the provided Dockerfile:

1. **Build the image**:
   ```bash
   podman build --build-arg NEXT_PUBLIC_SITE_URL=https://your-domain.com -t stegosaurust .
   ```

2. **Run the container**:
   ```bash
   podman run -d \
     -p 3000:3000 -p 8080:8080 \
     -e MINIO_ENDPOINT=http://your-minio-ip:9000 \
     -e MINIO_ACCESS_KEY=your_key \
     -e MINIO_SECRET_KEY=your_secret \
     -v stegosaurust_data:/app/data \
     --name stegosaurust stegosaurust
   ```

Note: The `NEXT_PUBLIC_SITE_URL` is baked into the frontend at build time for SEO and metadata metadataBase.

## API Documentation

Import the `backend/postman_collection.json` file into Postman to explore and test the API endpoints.

## License

MIT License - Built by Appsjuragan
