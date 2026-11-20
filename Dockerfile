# syntax=docker/dockerfile:1

FROM node:22-alpine AS base
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1

FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci

FROM base AS builder
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 trustrail \
  && adduser --system --uid 1001 trustrail \
  && mkdir -p /var/lib/trustrail/backups /app/.data \
  && chown -R trustrail:trustrail /var/lib/trustrail /app/.data

COPY --from=builder --chown=trustrail:trustrail /app/.next/standalone ./
COPY --from=builder --chown=trustrail:trustrail /app/.next/static ./.next/static
COPY --from=builder --chown=trustrail:trustrail /app/public ./public

USER trustrail
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
