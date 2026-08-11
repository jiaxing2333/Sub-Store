# 1. Build stage
FROM node:22-alpine AS builder

RUN corepack enable && corepack prepare pnpm@11.0.9 --activate

WORKDIR /app/backend

# Copy backend files
COPY backend/ ./

# Install dependencies ignoring lifecycle scripts (bypasses npx only-allow preinstall)
RUN pnpm install --no-frozen-lockfile --ignore-scripts

# Bundle backend
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
