FROM ghcr.io/puppeteer/puppeteer:latest
WORKDIR /app
COPY package.json ./
RUN npm install
COPY script.js .
CMD ["node", "script.js"]