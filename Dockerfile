FROM node:20-slim
WORKDIR /app
COPY package.json server.js ./
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/* \
    && curl -L -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip \
    && unzip -o /tmp/xray.zip -d /tmp/xraydl \
    && mv /tmp/xraydl/xray /app/xray && chmod +x /app/xray \
    && rm -rf /tmp/xray.zip /tmp/xraydl
EXPOSE 8080
CMD ["node", "server.js"]
