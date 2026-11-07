# Single image: the Go backend serves the statically exported Next.js UI.

# ---- frontend (static export) ----
FROM node:22-bookworm-slim AS web
ARG APP_VERSION=unknown
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_APP_VERSION=${APP_VERSION} \
    NEXT_PUBLIC_APP_COMMIT=${GIT_SHA} \
    NEXT_PUBLIC_APP_BUILD_DATE=${BUILD_DATE}
RUN npm run build

# ---- backend ----
FROM golang:1.24-bookworm AS api
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/stepca-ui ./cmd

# ---- runtime ----
FROM debian:bookworm-slim
# Pinned, checksum-verified step CLI (the backend shells out to it to obtain tokens and certificates)
ARG STEP_CLI_VERSION=0.30.6
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/* \
    && set -eux; cd /tmp \
    && curl -fLO "https://github.com/smallstep/cli/releases/download/v${STEP_CLI_VERSION}/step_linux_${TARGETARCH}.tar.gz" \
    && curl -fLO "https://github.com/smallstep/cli/releases/download/v${STEP_CLI_VERSION}/checksums.txt" \
    && grep "step_linux_${TARGETARCH}.tar.gz" checksums.txt | sha256sum -c - \
    && tar xz -C /tmp -f "step_linux_${TARGETARCH}.tar.gz" \
    && install -m 0755 "/tmp/step_linux_${TARGETARCH}/bin/step" /usr/local/bin/step \
    && rm -rf /tmp/step_linux_* /tmp/checksums.txt

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser
WORKDIR /app
COPY --from=api /out/stepca-ui /app/stepca-ui
COPY --from=web /web/out /app/web
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data
USER 10001

ARG APP_VERSION=unknown
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ENV APP_VERSION=${APP_VERSION} GIT_SHA=${GIT_SHA} BUILD_DATE=${BUILD_DATE} \
    GIN_MODE=release STEPPATH=/tmp/step PORT=8080 DB_PATH=/app/data/certs.db STATIC_DIR=/app/web
LABEL org.opencontainers.image.title="stepca-ui" \
      org.opencontainers.image.source="https://github.com/sctg-development/stepca-ui" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD curl -fsS http://localhost:8080/health || exit 1
ENTRYPOINT ["/app/stepca-ui"]
