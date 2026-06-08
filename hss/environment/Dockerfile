FROM node:20.11.1-bookworm-slim

ENV NODE_ENV=production
ENV CHROMIUM_PATH=/usr/bin/chromium
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium ca-certificates fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js worker.js ./
COPY entrypoint.sh /usr/local/sbin/hss-entrypoint.sh

RUN useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin hss \
    && useradd -m agent \
    && mkdir -p /app/output \
    && chown -R root:root /app /usr/local/sbin/hss-entrypoint.sh \
    && chmod 0755 /app \
    && find /app -type f -exec chmod 0644 {} \; \
    && find /app -type d -exec chmod 0755 {} \; \
    && chmod 0755 /usr/local/sbin/hss-entrypoint.sh \
    && chown agent:agent /app/output \
    && chmod 0700 /app/output

EXPOSE 1337

USER root
ENTRYPOINT ["/usr/local/sbin/hss-entrypoint.sh"]
