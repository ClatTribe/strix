FROM node:latest

WORKDIR /app

ENV STRIPE_KEY="sk-deadbeefDEADBEEF1234567890abcdef"

ADD https://example.com/install.sh /tmp/install.sh

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 3000

# No USER directive — runs as root.
CMD ["node", "app.js"]
