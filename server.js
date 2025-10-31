process.env.TZ = 'America/Boa_Vista';
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const SQLiteStore = require('connect-sqlite3')(session);

const PORT = process.env.PORT || 8080;
const BCRYPT_ROUNDS = 10;
const app = express();
const server = http.createServer(app);

const db = new sqlite3.Database('/data/database.sqlite');
db.run('PRAGMA journal_mode = WAL;');

function initializeDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      db.run(`CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY, nome TEXT, tipo TEXT, login TEXT UNIQUE, senha TEXT)`);
      db.run(`CREATE TABLE IF NOT EXISTS pendencias (id INTEGER PRIMARY KEY, placa TEXT, descricao TEXT, status TEXT, criador_id INTEGER, despachante_id INTEGER, criado_em DATETIME, resolvido_em DATETIME)`);
      
      // Gera o hash da senha 'admin'
      bcrypt.hash('admin', BCRYPT_ROUNDS, (err, hashed) => {
        if (err) return reject(err);

        const sql = `INSERT OR IGNORE INTO usuarios (nome, tipo, login, senha) VALUES (?, 'admin', 'admin', ?)`;
        db.run(sql, ['Administrador', hashed], function(err) {
          if (err) return reject(err);
          if (this.changes > 0) console.log('USUÁRIO "admin" COM SENHA "admin" CRIADO COM SUCESSO.');
          else console.log('Usuário "admin" já existe. Nenhuma ação necessária.');
          resolve();
        });
      });
    });
  });
}

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(bodyParser.json());

const sessionParser = session({
  store: new SQLiteStore({
    client: db
  }),
  saveUninitialized: false,
  secret: process.env.SESSION_SECRET || 'uma_chave_secreta_modifique_em_producao',
  resave: false,
  cookie: {
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production'
  }
});
app.use(sessionParser);

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
  {
    usernameField: 'login',    // Diz ao Passport para usar o campo 'login'
    passwordField: 'senha'     // Diz ao Passport para usar o campo 'senha'
  },
  function(login, senha, done) { // Os parâmetros aqui continuam os mesmos
    db.get("SELECT * FROM usuarios WHERE login = ?", [login], async (err, user) => {
      if (err) { return done(err); }
      if (!user) { return done(null, false, { message: 'Usuário não encontrado.' }); }
      
      const passwordMatch = await bcrypt.compare(senha, user.senha);
      if (!passwordMatch) { return done(null, false, { message: 'Senha incorreta.' }); }
      
      return done(null, user);
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  db.get("SELECT id, nome, tipo FROM usuarios WHERE id = ?", [id], (err, user) => {
    if (err) return done(err);
    done(null, user);
  });
});

app.use((req, res, next) => {
  const time = new Date().toISOString();
  console.log(`[${time}] REQUISIÇÃO: ${req.method} ${req.originalUrl} | SessionID: ${req.sessionID}`);
  next();
});
const isAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user.tipo === 'admin') return next();
    res.status(403).json({ error: 'Acesso negado' });
};

app.post('/api/register', async (req, res) => {
  const { nome, tipo, login, senha } = req.body;
  if (!nome || !tipo || !login || !senha || tipo === 'admin') return res.status(400).json({ error: 'Dados inválidos' });
  try {
    const hashed = await bcrypt.hash(senha, BCRYPT_ROUNDS);
    db.run("INSERT INTO usuarios (nome, tipo, login, senha) VALUES (?, ?, ?, ?)", [nome, tipo, login, hashed], function(err) {
      if (err) return res.status(400).json({ error: 'Login já existe' });
      res.json({ message: 'Usuário cadastrado' });
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.post('/api/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) { return res.status(401).json({ error: 'Credenciais incorretas' }); }
    
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      
      if (req.body.manterConectado) {
        req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 dias
      }
      
      return res.json({ user: { id: user.id, nome: user.nome, tipo: user.tipo } });
    });
  })(req, res, next);
});

app.post('/api/logout', (req, res) => {
  req.logout(() => {
    res.json({ ok: true });
  });
});
app.get('/api/session', (req, res) => {
  if (req.isAuthenticated()) return res.json({ user: req.user });
  res.status(401).json({ error: 'Não autenticado' });
});
app.get('/api/despachantes', async (req, res) => {
  db.all("SELECT id, nome FROM usuarios WHERE tipo = 'despachante'", (err, rows) => {
    if (err) return res.status(500).json({ error: 'Erro no banco de dados' });
    res.json({ despachantes: rows || [] });
  });
});
app.get('/api/pendencias', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Não autenticado' });
  const userId = req.user.id;
  db.all(
    `SELECT p.*, u.nome as criador_nome, d.nome as despachante_nome FROM pendencias p JOIN usuarios u ON p.criador_id = u.id JOIN usuarios d ON p.despachante_id = d.id WHERE (p.criador_id = ? OR p.despachante_id = ?) AND p.status != 'triado' ORDER BY p.criado_em DESC`,
    [userId, userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Erro no banco de dados' });
      res.json({ pendencias: rows || [] });
    }
  );
});
app.post('/api/pendencias', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Não autenticado' });
  const { placa, descricao, despachante_id } = req.body;
  const criador_id = req.user.id;
  db.run("INSERT INTO pendencias (placa, descricao, criador_id, despachante_id, status, criado_em) VALUES (?, ?, ?, ?, 'pendente', datetime('now'))", 
    [placa, descricao || '', criador_id, despachante_id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Erro ao criar pendência' });
      broadcastUpdate();
      res.json({ message: 'Pendência criada' });
    }
  );
});
app.get('/api/admin/users', isAdmin, async (req, res) => {
    db.all("SELECT id, nome, tipo, login FROM usuarios", (err, rows) => {
        if (err) return res.status(500).json({ error: 'Erro no banco de dados' });
        res.json(rows || []);
    });
});
app.put('/api/admin/users/:id', isAdmin, async (req, res) => {
    const { nome, tipo, login, senha } = req.body;
    try {
        if (senha) {
            const hashed = await bcrypt.hash(senha, BCRYPT_ROUNDS);
            db.run("UPDATE usuarios SET nome=?, tipo=?, login=?, senha=? WHERE id=?", [nome, tipo, login, hashed, req.params.id], function(err) {
                if (err) return res.status(500).json({ error: 'Erro ao atualizar usuário' });
                res.json({ message: 'Usuário atualizado' });
            });
        } else {
            db.run("UPDATE usuarios SET nome=?, tipo=?, login=? WHERE id=?", [nome, tipo, login, req.params.id], function(err) {
                if (err) return res.status(500).json({ error: 'Erro ao atualizar usuário' });
                res.json({ message: 'Usuário atualizado' });
            });
        }
    } catch (err) {
        res.status(500).json({ error: 'Erro no servidor' });
    }
});
app.delete('/api/admin/users/:id', isAdmin, async (req, res) => {
    if (req.user.id == req.params.id) return res.status(400).json({ error: 'Não pode deletar a si mesmo' });
    db.run("DELETE FROM usuarios WHERE id = ?", [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Erro ao deletar usuário' });
        res.json({ message: 'Usuário deletado' });
    });
});
app.get('/api/admin/pendencias', isAdmin, async (req, res) => {
    try {
        db.all(
        `SELECT p.*, u_criador.nome as criador_nome, u_despachante.nome as despachante_nome
        FROM pendencias p
        LEFT JOIN usuarios u_criador ON p.criador_id = u_criador.id
        LEFT JOIN usuarios u_despachante ON p.despachante_id = u_despachante.id
        ORDER BY p.criado_em DESC`, (err, rows) => {
            if (err) return res.status(500).json({ error: 'Erro DB' });
            res.json(rows || []);
        }
        );
    } catch (err) {
        res.status(500).json({ error: 'Erro DB' });
    }
});
app.put('/api/admin/pendencias/:id', isAdmin, async (req, res) => {
    const { placa, descricao, status } = req.body;
    db.run("UPDATE pendencias SET placa = ?, descricao = ?, status = ? WHERE id = ?", [placa, descricao, status, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Erro ao atualizar pendência' });
        broadcastUpdate();
        res.json({ message: 'Pendência atualizada com sucesso.' });
    });
});
app.delete('/api/admin/pendencias/:id', isAdmin, async (req, res) => {
    db.run("DELETE FROM pendencias WHERE id = ?", [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Erro ao deletar pendência' });
        broadcastUpdate();
        res.json({ message: 'Pendência deletada' });
    });
});

const wss = new WebSocket.Server({ noServer: true });
const clientsByUserId = new Map();

async function broadcastUpdate() {
    for (const client of wss.clients) {
        if (client.readyState === WebSocket.OPEN && client.session.user) {
            const userId = client.session.user.id;
            db.all(
                `SELECT p.*, u.nome as criador_nome, d.nome as despachante_nome FROM pendencias p JOIN usuarios u ON p.criador_id = u.id JOIN usuarios d ON p.despachante_id = d.id WHERE (p.criador_id = ? OR p.despachante_id = ?) AND p.status != 'triado' ORDER BY p.criado_em DESC`,
                [userId, userId],
                (err, rows) => {
                    if (err) return;
                    if(rows) client.send(JSON.stringify({ type: 'update', pendencias: rows }));
                }
            );
        }
    }
}

server.on('upgrade', (request, socket, head) => {
  sessionParser(request, {}, () => {
    if (!request.session.passport || !request.session.passport.user) {
      return socket.destroy();
    }
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.session = request.session;
      wss.emit('connection', ws, request);
    });
  });
});

wss.on('connection', (ws, request) => {
  const user = request.session.user;
  clientsByUserId.set(String(user.id), ws);
  broadcastUpdate();

  ws.on('message', async (message) => {
    const msg = JSON.parse(message.toString());
    const { type, pendenciaId, descricao } = msg;
    if (!type || !pendenciaId) return;

    try {
        if (type === 'reabrir') {
          if (ws.session.user.tipo !== 'funcionario') {
            return ws.send(JSON.stringify({ type: 'error', message: 'Apenas funcionários podem reabrir pendências.' }));
          }
          db.run("UPDATE pendencias SET status = 'pendente', descricao = ?, resolvido_em = NULL WHERE id = ?", [descricao, pendenciaId]);
        }
    
        if (type === 'resolver' || type === 'pendente') {
            if (ws.session.user.tipo !== 'despachante') {
                return ws.send(JSON.stringify({ type: 'error', message: 'Ação não permitida para seu perfil.' }));
            }
            db.get("SELECT * FROM pendencias WHERE id = ?", [pendenciaId], (err, pendencia) => {
                if (err || !pendencia) return;
                if (type === 'resolver') {
                    db.run("UPDATE pendencias SET status = ?, resolvido_em = datetime('now') WHERE id = ?", ['resolvido', pendenciaId]);
                } else { // type === 'pendente'
                    db.run("UPDATE pendencias SET status = ?, resolvido_em = NULL WHERE id = ?", ['pendente', pendenciaId]);
                }
            });
        }
        broadcastUpdate();
    } catch (err) {
        console.error("Erro no WebSocket:", err);
    }
  });

  ws.on('close', () => clientsByUserId.delete(String(user.id)));
});

async function startServer() {
  try {
    await initializeDatabase();
    console.log("Banco de dados inicializado e verificado.");
    server.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
  } catch (err) {
    console.error("FALHA CRÍTICA AO INICIAR O SERVIDOR:", err);
    process.exit(1);
  }
}

startServer();

app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});