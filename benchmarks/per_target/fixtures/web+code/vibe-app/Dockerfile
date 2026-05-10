FROM node:18-alpine

WORKDIR /app
COPY src/package.json src/package-lock.json ./
RUN npm install --omit=dev --no-fund --no-audit
COPY src/app.js ./

EXPOSE 3030
CMD ["node", "app.js"]
