FROM oven/bun:alpine AS builder
WORKDIR /app
COPY package*.json bun.lock* ./
RUN bun install --frozen-lockfile || bun install
COPY tsconfig.json ./
COPY src/ ./src/
RUN bun run build:prod

FROM oven/bun:alpine
RUN addgroup -g 1001 -S mcpuser && adduser -u 1001 -S mcpuser -G mcpuser
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder --chown=mcpuser:mcpuser /app/dist/index.js ./dist/index.js
COPY --chown=mcpuser:mcpuser src/rules/security-rules.json ./dist/rules/security-rules.json
USER mcpuser
CMD ["bun", "run", "dist/index.js"]
