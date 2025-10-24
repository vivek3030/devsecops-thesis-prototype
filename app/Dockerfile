# --- Build Stage ---
# Use an official Go image as the base for building
FROM golang:1.21-alpine AS build

WORKDIR /src
# Copy Go module files and download dependencies
# This is done first to leverage Docker layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code and build the application
COPY . .
# Build a statically-linked binary to run in a minimal container
RUN CGO_ENABLED=0 go build -o /app/server .

# --- Final Stage ---
# Use a minimal alpine image for the final container
FROM alpine:3.18

# Copy the built binary from the build stage
COPY --from=build /app/server /usr/local/bin/server

# Expose the port the server runs on
EXPOSE 8080
# The command to run when the container starts
CMD ["/usr/local/bin/server"]

