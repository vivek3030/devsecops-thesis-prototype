# ============================================
# SLSA L3 Compliant Multi-Architecture Dockerfile
# Using Chainguard Images (TAGGED)
# ============================================

# --- Build Stage ---
FROM cgr.dev/chainguard/go:1.22 AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG BUILD_DATE
ARG VCS_REF

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

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

# --- Final Stage ---
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
      org.opencontainers.image.authors="Vivekkumar Kasundra"

COPY --from=build /app/server /usr/local/bin/server

USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]
