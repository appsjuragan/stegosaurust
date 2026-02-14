FROM rust:slim-bookworm AS backend-builder

WORKDIR /app
COPY backend ./backend
WORKDIR /app/backend

# Install dependencies for Rust build
RUN apt-get update && apt-get install -y pkg-config libssl-dev gcc libc6-dev

# Build (Release)
RUN cargo build --release

# --- Frontend Builder ---
FROM oven/bun:slim AS frontend-builder

WORKDIR /app
COPY package.json bun.lock tsconfig.json next.config.ts tailwind.config.ts postcss.config.mjs components.json ./
COPY src ./src
COPY public ./public

# Install dependencies
RUN bun install

ARG NEXT_PUBLIC_SITE_URL
ENV NEXT_PUBLIC_SITE_URL=$NEXT_PUBLIC_SITE_URL

# Build Next.js
# Note: "next build" outputs to .next/standalone
RUN bun run build

# --- Runtime ---
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Backend Binary
COPY --from=backend-builder /app/backend/target/release/stegosaurust-backend /app/backend

# Copy Frontend Standalone
COPY --from=frontend-builder /app/.next/standalone ./
COPY --from=frontend-builder /app/public ./public
COPY --from=frontend-builder /app/.next/static ./.next/static

# Set Environment defaults
ENV NODE_ENV=production
ENV HOSTNAME="0.0.0.0"
ENV PORT=3000
# Backend listens on 8080 by default
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8080
ENV DATA_DIR=/app/data

# Create data directory
RUN mkdir -p /app/data

# Startup script
COPY <<EOF /app/start.sh
#!/bin/bash
set -e

# Start Backend in background
echo "Starting Backend..."
./backend &

# Wait for backend (optional, simple sleep)
sleep 2

# Start Frontend
echo "Starting Frontend..."
node server.js
EOF

RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
