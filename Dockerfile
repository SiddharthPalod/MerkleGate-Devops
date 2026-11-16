# Multi-stage Dockerfile for MerkleGate
FROM golang:alpine AS builder
WORKDIR /app

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/visualizer ./cmd/visualizer

# Minimal scratch/alpine runtime
FROM alpine:3.20
RUN apk --no-cache add ca-certificates
WORKDIR /app

COPY --from=builder /bin/visualizer /app/visualizer

# Mountable directories for tiles and keys
VOLUME ["/app/data", "/app/keys"]

EXPOSE 8080

ENTRYPOINT ["/app/visualizer"]
