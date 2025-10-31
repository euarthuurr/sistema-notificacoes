FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install

RUN mkdir /data

COPY . .

EXPOSE 8080

CMD ["npm", "start"]
