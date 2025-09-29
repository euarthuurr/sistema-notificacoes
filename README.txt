
# Sistema de Notificação de Pendências (Modo Escuro)

Este é um protótipo atualizado do sistema de notificações entre Funcionários do DETRAN e Despachantes,
com **layout em modo escuro**, utilizando Bootstrap 5 e FontAwesome.

## 📂 Conteúdo do pacote
- server.js → Servidor Node.js (Express + WebSocket + SQLite + express-session + bcrypt)
- package.json → Dependências do projeto
- /public/index.html → Tela de login/cadastro
- /public/painel.html → Painel principal com notificações
- /public/style.css → Estilos customizados (modo escuro)
- README.txt → Este guia

## 🚀 Como executar
1. Certifique-se de ter o Node.js instalado (https://nodejs.org).

2. Extraia o conteúdo do .zip em uma pasta.

3. No terminal, dentro da pasta, rode:
   ```bash
   npm install
   node server.js
   ```

4. Abra no navegador:
   ```
   http://localhost:8080/
   ```

5. Use **duas abas** para simular um Funcionário e um Despachante.

## 🛠️ Funcionalidades
- Funcionários podem cadastrar pendências para despachantes.
- Despachantes recebem notificações em tempo real.
- Quando resolvidas, os funcionários recebem a confirmação.
- Tudo é persistido em SQLite.
- Senhas são armazenadas com hash (bcrypt).
- Sessões com cookie (express-session).
- Layout moderno em modo escuro.

