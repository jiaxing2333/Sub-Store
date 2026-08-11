# 1. Build stage
FROM node:22-alpine AS builder

RUN corepack enable && corepack prepare pnpm@11.0.9 --activate

WORKDIR /app/backend

# Copy package files and patches directory required by pnpm patchedDependencies
COPY backend/package.json backend/pnpm-lock.yaml ./
COPY backend/patches/ ./patches/

# Allow built dependencies for pnpm 10+
ENV PNPM_CONFIG_ONLY_BUILT_DEPENDENCIES="core-js,esbuild,nodemon"

RUN pnpm install --no-frozen-lockfile

COPY backend/ ./
RUN pnpm bundle:esbuild

# 2. Runtime stage
FROM node:22-alpine

WORKDIR /app

COPY --from=builder /app/backend/sub-store.min.js ./

# Default environment variables
ENV SUB_STORE_BACKEND_API_HOST=0.0.0.0
ENV SUB_STORE_BACKEND_API_PORT=3001
ENV SUB_STORE_DATA_BASE_PATH=/opt/app/data

EXPOSE 3001
VOLUME [ "/opt/app/data" ]

CMD ["node", "sub-store.min.js"]
