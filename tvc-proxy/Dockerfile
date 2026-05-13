# ── Build stage ─────────────────────────────────────────────────────────────
# Bundles the TypeScript source + all npm deps into a single CJS file (proxy.cjs)
# so the TVC pivot digest attests the entire application in one hash.
FROM node:22-alpine AS builder

WORKDIR /build

COPY package.json ./
# Install all deps including devDeps (esbuild, typescript)
RUN npm install

COPY tsconfig.json index.ts ./
# Type-check, then bundle
RUN npm run typecheck && npm run build

# ── Runtime stage ────────────────────────────────────────────────────────────
# Minimal image: Node 22 alpine + the single bundled file.
# The container image @sha256 digest + the sha256 of /app/proxy.cjs are what
# TVC attestation verifies via expectedPivotDigest.
FROM node:22-alpine

WORKDIR /app

COPY --from=builder /build/proxy.cjs ./proxy.cjs

# Health check endpoint hit by TVC's readiness probe
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD wget -qO- http://localhost:${PORT:-3000}/health || exit 1

EXPOSE 3000

# TVC deployment config:
#   "pivotPath": "/usr/local/bin/node"
#   "pivotArgs": "/app/proxy.cjs"
#   "publicIngressPort": 443
#   "healthCheckPort": 3000
#   "healthCheckType": "TVC_HEALTH_CHECK_TYPE_HTTP"
ENTRYPOINT ["/usr/local/bin/node", "/app/proxy.cjs"]
