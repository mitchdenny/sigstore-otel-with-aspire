FROM node:24.15.0-bookworm-slim

ENV NODE_ENV=production \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY client.mjs trust-status.mjs ./

USER node

EXPOSE 8080
ENTRYPOINT ["node", "/app/client.mjs"]
