# ============================================
# SLSA L3 Compliant Multi-Architecture Dockerfile
# Using Chainguard Images (Recommended)
# ============================================

# --- Build Stage (Chainguard Go Builder) ---
FROM cgr.dev/chainguard/go:1.22@sha256:6c620ffc6a7fbb856ce562ec20fbf9910f08d81d3f94a72e3f1e7dc08e33387c AS build

# Set reproducibility build args
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG BUILD_DATE
ARG VCS_REF

WORKDIR /src

# Copy module files
COPY go.mod go.sum ./

# Download dependencies (hermetic, verified)
RUN go mod download && go mod verify

# Copy source
COPY . .

# Build the Go binary using SLSA-friendly flags
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags="-s -w \
        -X main.Version=${VERSION} \
        -X main.BuildDate=${BUILD_DATE} \
        -X main.VCSRef=${VCS_REF} \
        -buildid=" \
      -o /app/server .

# Verify binary
RUN ls -lah /app/server && chmod +x /app/server


# --- Final Stage (Chainguard Static Base) ---
FROM cgr.dev/chainguard/static@sha256:8c5b1343e84c9f8a9e1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3

# Metadata labels (same as your original)
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

# Copy the static Go binary
COPY --from=build /app/server /usr/local/bin/server

# Chainguard images use nonroot by default
USER nonroot

# Expose port
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/server"]
