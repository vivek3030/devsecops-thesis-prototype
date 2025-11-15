# ============================================
# SLSA L3 Hardened Multi-Architecture Dockerfile
# Using Chainguard Images (TAGGED)
# ============================================

# --- Build Stage ---
FROM cgr.dev/chainguard/go:latest-dev AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG BUILD_DATE
ARG VCS_REF

WORKDIR /src

# Ensure go.sum integrity
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# Build securely
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags="-s -w \
        -X main.Version=${VERSION} \
        -X main.BuildDate=${BUILD_DATE} \
        -X main.VCSRef=${VCS_REF}" \
      -o /app/server .

# --- Final Stage (distroless, secure) ---
FROM cgr.dev/chainguard/static:latest

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
      org.opencontainers.image.authors="Vivekkumar Kasundra" \
      # Security best practices
      org.opencontainers.image.base.name="cgr.dev/chainguard/static" \
      org.opencontainers.image.licenses="Apache-2.0"

# Copy binary
COPY --from=build /app/server /usr/local/bin/server

# Drop privileges
USER nonroot

# Avoid running as root AND avoid writable root filesystem
# (Chainguard static already uses read-only FS)
EXPOSE 8080

# Set minimal environment
ENV GODEBUG=madvdontneed=1 \
    TZ=UTC

# Security: no shell, no /bin/sh, distroless model
ENTRYPOINT ["/usr/local/bin/server"]
