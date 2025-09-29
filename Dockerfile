# Dockerfile para a aplicação Node.js

# 1. Escolha da imagem base
# Usamos uma imagem oficial do Node.js na versão 18, baseada no Alpine Linux por ser leve.
FROM node:18-alpine

# 2. Definição do diretório de trabalho dentro do container
# Todos os comandos a seguir serão executados a partir deste diretório.
WORKDIR /usr/src/app

# 3. Copia dos arquivos de dependência
# Copiamos o package.json (e o package-lock.json, se existir) primeiro.
# Isso aproveita o cache do Docker: se esses arquivos não mudarem,
# a demorada etapa de `npm install` não será executada novamente.
COPY package*.json ./

# 4. Instalação das dependências
# O `npm install` baixa e instala tudo que está listado no package.json.
# Usamos `--only=production` em um ambiente de produção para não instalar dependências de desenvolvimento.
# Para este caso, vamos instalar todas para garantir que tudo funcione.
RUN npm install

# Cria o diretório para o banco de dados e define as permissões corretas

# 5. Copia do código-fonte da aplicação
# Com as dependências instaladas, copiamos o restante dos arquivos da aplicação.
COPY . .

# 6. Exposição da porta
# A aplicação roda na porta 8080 (definido em server.js).
# O comando EXPOSE informa ao Docker que o container escutará nesta porta.
EXPOSE 8080

# 7. Comando para iniciar a aplicação
# Este é o comando que será executado quando o container iniciar.
# Ele executa o script "start" definido no seu package.json.
CMD [ "npm", "start" ]
