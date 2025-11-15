# ============================================
# SLSA L3 Compliant Dockerfile (Alpine-based with Health Check)
# ============================================
# Alternative to distroless for environments requiring health checks

# --- Build Stage ---
FROM golang:1.21-alpine@sha256:445f34008a77b0b98bf1821bf7ef5e37bb63cc42d22ee7c21cc17041070d134f AS build

# Set build arguments for reproducibility
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG BUILD_DATE
ARG VCS_REF

# Install build dependencies
RUN apk add --no-cache \
    ca-certificates \
    git

WORKDIR /src

# Copy Go module files first (better layer caching)
COPY go.mod go.sum ./

# Download dependencies with verification
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build statically-linked binary with security flags
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build \
    -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE} -X main.VCSRef=${VCS_REF}" \
    -o /app/server \
    .

# Verify the binary
RUN file /app/server && \
    chmod +x /app/server

# --- Final Stage ---
# Use minimal Alpine image (smaller than distroless but includes shell for health checks)
FROM alpine:3.19@sha256:51b67269f354137895d43f3b3d810bfacd3945438e94dc5ac55fdac340352f48

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata && \
    addgroup -g 65532 -S nonroot && \
    adduser -u 65532 -S nonroot -G nonroot

# Add labels for metadata
LABEL org.opencontainers.image.title="SLSA L3 Demo Application" \
      org.opencontainers.image.description="Secure Go application with SLSA L3 compliance" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/vivek3030/devsecops-thesis-prototype" \
      security.slsa.level="3" \
      org.opencontainers.image.vendor="Hochschule Albstadt-Sigmaringen" \
      org.opencontainers.image.authors="Vivekkumar Kasundra"

# Copy the statically-linked binary from build stage
COPY --from=build /app/server /usr/local/bin/server

# Use non-root user
USER nonroot:nonroot

# Expose application port
EXPOSE 8080

# Health check using the application's built-in health endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/server", "-health"]

# Run the application
ENTRYPOINT ["/usr/local/bin/server"]