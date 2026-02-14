# --- Backend Builder ---
FROM rust:slim-bookworm AS backend-builder

WORKDIR /app
COPY backend ./backend
WORKDIR /app/backend

# Install dependencies for Rust build
RUN apt-get update && apt-get install -y pkg-config libssl-dev gcc libc6-dev binutils && \
    rm -rf /var/lib/apt/lists/*

# Build (Release)
RUN cargo build --release && \
    strip target/release/stegosaurust-backend && \
    mv target/release/stegosaurust-backend /app/stegosaurust-backend

# --- Frontend Builder ---
FROM oven/bun:slim AS frontend-builder

WORKDIR /app
COPY package.json bun.lock tsconfig.json next.config.ts tailwind.config.ts postcss.config.mjs components.json ./
COPY src ./src
COPY public ./public

# Install dependencies
RUN bun install --frozen-lockfile

ARG NEXT_PUBLIC_SITE_URL
ENV NEXT_PUBLIC_SITE_URL=$NEXT_PUBLIC_SITE_URL

# Build Next.js
RUN bun run build && \
    rm -rf .next/cache

# --- Runtime ---
FROM node:20-slim

# Install minimal runtime deps
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Backend Binary
COPY --from=backend-builder /app/stegosaurust-backend ./backend

# Copy Frontend Standalone
COPY --from=frontend-builder /app/.next/standalone ./
COPY --from=frontend-builder /app/public ./public
COPY --from=frontend-builder /app/.next/static ./.next/static

# Set Environment defaults
ENV NODE_ENV=production
ENV HOSTNAME="0.0.0.0"
ENV PORT=3000
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8080
ENV DATA_DIR=/app/data

# Create data directory
RUN mkdir -p /app/data

# Startup script (Inline for minimal layers)
RUN echo '#!/bin/bash\n./backend &\nsleep 2\nexec node server.js' > /app/start.sh && \
    chmod +x /app/start.sh

EXPOSE 3000 8080

CMD ["/app/start.sh"]
