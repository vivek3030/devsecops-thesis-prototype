# ============================================
# SLSA L3 Compliant Multi-Architecture Dockerfile
# ============================================

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

# Verify the binary exists and is executable
RUN ls -lah /app/server && \
    chmod +x /app/server

# --- Final Stage ---
FROM gcr.io/distroless/static-debian12:nonroot@sha256:6dcc833df2a475be1a3d7fc96eac92eb5799c892f553d0f5b3744e66d44e7c16

# Add labels for metadata
ARG VERSION=dev
ARG BUILD_DATE
ARG VCS_REF

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

# Use non-root user (distroless nonroot is UID 65532)
USER 65532:65532

# Expose application port
EXPOSE 8080

# Run the application
ENTRYPOINT ["/usr/local/bin/server"]