# Pro Glass Chat — تشغيل الإنتاج في حاوية
FROM node:20-alpine
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev --no-audit --no-fund

COPY server.js ./
COPY scripts ./scripts
COPY public ./public

ENV NODE_ENV=production
ENV HOST=0.0.0.0
EXPOSE 3000

CMD ["node", "server.js"]
