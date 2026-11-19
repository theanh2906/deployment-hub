# syntax=docker/dockerfile:1

# Stage 1: Build static Go binary with embedded web/index.html
FROM golang:1.22-alpine AS builder
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/deploymenthub ./cmd/deploymenthub

# Stage 2: Minimal Alpine runtime (~25MB)
FROM alpine:3.20 AS runner
RUN apk add --no-cache ca-certificates git tzdata \
    && addgroup -S -g 10001 hub \
    && adduser -S -u 10001 -G hub hub \
    && mkdir -p /data/traefik-dynamic \
    && chown -R hub:hub /data

WORKDIR /app
COPY --from=builder /out/deploymenthub /usr/local/bin/deploymenthub
# Keep web assets alongside binary as optional disk override reference
COPY --from=builder --chown=hub:hub /src/web /app/web

USER hub
EXPOSE 4180
ENV PORT=4180

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:4180/api/v1/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/deploymenthub"]
