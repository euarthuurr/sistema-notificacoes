# Backend: Express API com WebSocket e SQLite
FROM node:22-alpine3.21

WORKDIR /app

# Copia os arquivos de dependência do backend
COPY package.json package-lock.json ./

# Instala as dependências do backend
RUN npm ci

# Copia o restante do código do backend (excluindo node_modules)
COPY --chown=node:node . .

# Remove arquivos desnecessários (mantém node_modules)
RUN rm -rf .git .gitignore .dockerignore docker-compose.yml Dockerfile bkp-* bkp-node_modules *.db* julius-scratch .nuxt .output dist

EXPOSE 8080

CMD ["npm", "start"]