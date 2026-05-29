# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /bin/auth-service \
    ./cmd/api

FROM alpine:3.21

RUN apk add --no-cache ca-certificates wget

RUN addgroup -S app && adduser -S app -G app

WORKDIR /app

COPY --from=builder /bin/auth-service /app/auth-service
COPY config/config.yaml /app/config/config.yaml

USER app

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/auth-service"]
