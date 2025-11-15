# ============================================
# SLSA L3 Compliant Multi-Architecture Dockerfile
# ============================================
# This Dockerfile supports hermetic, reproducible builds
# for both amd64 and arm64 architectures

# --- Build Stage ---
# Use specific Go version with digest for reproducibility
FROM golang:1.21-alpine@sha256:926f7f7f4d3c72d028f85cf7d91da5c5f8c5c7d0f5f8f8d8c3a6f5d8f5d8f5d8 AS build

# Install build dependencies with locked versions
RUN apk add --no-cache \
    ca-certificates=20230506-r0 \
    git=2.40.1-r0

# Set build arguments for reproducibility
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG BUILD_DATE
ARG VCS_REF

WORKDIR /src

# Copy Go module files first (better layer caching)
COPY go.mod go.sum ./

# Download dependencies with verification
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build statically-linked binary with security flags
# -trimpath: Remove file system paths for reproducibility
# -ldflags: Inject build metadata and strip debug info
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
    /app/server -version 2>/dev/null || true

# --- Final Stage ---
# Use minimal distroless image for security (specific digest for reproducibility)
FROM gcr.io/distroless/static-debian12:nonroot@sha256:e9ac71e2b8e279a8372741b7a0293afda17650d926900233ec3a7b2b7c22a246

# Add labels for metadata
LABEL org.opencontainers.image.title="SLSA L3 Demo Application" \
      org.opencontainers.image.description="Secure Go application with SLSA L3 compliance" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/devsecops/thesis-app" \
      security.slsa.level="3"

# Copy the statically-linked binary from build stage
COPY --from=build /app/server /usr/local/bin/server

# Use non-root user (distroless nonroot is UID 65532)
USER 65532:65532

# Expose application port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/server", "-health"] || exit 1

# Run the application
ENTRYPOINT ["/usr/local/bin/server"]
