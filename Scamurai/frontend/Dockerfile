FROM node:22.12.0-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN npm run build
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 4173

CMD ["/app/docker-entrypoint.sh"]
