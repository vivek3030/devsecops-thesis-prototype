# ==============================================================================
# SLSA L3 Secure Dockerfile
# ==============================================================================

# --- Build Stage ---
FROM cgr.dev/chainguard/go:1.23-dev AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG BUILD_DATE
ARG VCS_REF

WORKDIR /src

# Copy module files first – verify checksums
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build static binary with security flags
RUN CGO_ENABLED=0 \
  GOOS=${TARGETOS} \
  GOARCH=${TARGETARCH} \
  go build \
  -trimpath \
  -ldflags="-s -w \
  -X main.Version=${VERSION} \
  -X main.BuildDate=${BUILD_DATE} \
  -X main.VCSRef=${VCS_REF} \
  -extldflags '-static'" \
  -o /app/server .

# Verify binary is statically linked
RUN file /app/server | grep "statically linked" || \
  (echo "ERROR: Binary is not statically linked!" && exit 1)

# --- Final Stage ---
FROM cgr.dev/chainguard/static:latest

ARG VERSION=dev
ARG BUILD_DATE
ARG VCS_REF

# OCI Image Labels
LABEL org.opencontainers.image.title="SLSA L3 Demo Application" \
  org.opencontainers.image.description="Secure Go application with SLSA L3 compliance" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.created="${BUILD_DATE}" \
  org.opencontainers.image.revision="${VCS_REF}" \
  org.opencontainers.image.vendor="Your Organization" \
  org.opencontainers.image.licenses="MIT" \
  org.opencontainers.image.source="https://github.com/vivek3030/devsecops-thesis-prototype" \
  security.slsa.level="3" \
  security.scan.date="${BUILD_DATE}"

# Set working directory
WORKDIR /app

# Copy binary from build stage
COPY --from=build --chown=nonroot:nonroot /app/server /usr/local/bin/server

# Switch to non-root user (UID 65532 is 'nonroot' in Chainguard)
USER 65532:65532

# Expose port
EXPOSE 8080/tcp

# Environment variables
ENV GODEBUG=madvdontneed=1 \
  TZ=UTC \
  PORT=8080

# Use exec form for proper signal handling
ENTRYPOINT ["/usr/local/bin/server"]
CMD []