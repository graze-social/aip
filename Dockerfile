# Build stage
FROM rust:1.87-slim AS builder

# Install required system dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock build.rs ./

ARG FEATURES=embed,postgres
ARG TEMPLATES=./templates
ARG STATIC=./static

# Copy actual source code and assets
COPY src ./src
COPY migrations ./migrations
COPY ${TEMPLATES} ./templates
COPY ${STATIC} ./static

ENV HTTP_TEMPLATE_PATH=/app/templates/

# Build the actual application with embed feature only
RUN cargo build --release --no-default-features --features ${FEATURES}

# Runtime stage using distroless
FROM gcr.io/distroless/cc-debian12

# Add OCI labels
LABEL org.opencontainers.image.title="aip"
LABEL org.opencontainers.image.description="A Placeholder Description"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="Nick Gerakines <nick.gerakines@gmail.com>"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.created="2025-01-06T00:00:00Z"

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/aip /app/aip

# Copy static directory
COPY --from=builder /app/static ./static

# Set environment variables
ENV HTTP_STATIC_PATH=/app/static
ENV HTTP_PORT=8080

# Expose port
EXPOSE 8080

# Run the application
ENTRYPOINT ["/app/aip"]