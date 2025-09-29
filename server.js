
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
const cookieParser = require('cookie-parser');

// --- Helper Functions ---
function isSameDay(dateString) {
    if (!dateString) return false;
    const date = new Date(dateString);
    const today = new Date();
    return date.getFullYear() === today.getFullYear() &&
           date.getMonth() === today.getMonth() &&
           date.getDate() === today.getDate();
}

// --- Basic Setup ---
const DBSOURCE = "database.sqlite";
const PORT = process.env.PORT || 8080;
const BCRYPT_ROUNDS = 10;
const app = express();

// --- Database Initialization ---
const db = new sqlite3.Database(DBSOURCE, (err) => {
  if (err) return console.error("Erro ao conectar ao DB:", err);
  console.log("Conectado ao SQLite.");

  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT, tipo TEXT, login TEXT UNIQUE, senha TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS pendencias (id INTEGER PRIMARY KEY AUTOINCREMENT, placa TEXT, descricao TEXT, status TEXT, criador_id INTEGER, despachante_id INTEGER, criado_em DATETIME, resolvido_em DATETIME)`);
    
    db.get("SELECT * FROM usuarios WHERE tipo = 'admin'", async (err, row) => {
        if (!row) {
            console.log('Criando usuário admin padrão...');
            const hashed = await bcrypt.hash('admin', BCRYPT_ROUNDS);
            db.run("INSERT INTO usuarios (nome, tipo, login, senha) VALUES ('Administrador', 'admin', 'admin', ?)", [hashed]);
        }
    });
  });
});

// --- Middleware Setup ---
app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());
const sessionParser = session({
  saveUninitialized: false,
  secret: 'uma_chave_secreta_modifique_em_producao',
  resave: false,
  cookie: { maxAge: 1000 * 60 * 60 }
});
app.use(sessionParser);

// --- API Routes ---
const isAdmin = (req, res, next) => {
    if (req.session && req.session.user && req.session.user.tipo === 'admin') return next();
    res.status(403).json({ error: 'Acesso negado' });
};

app.post('/api/register', async (req, res) => {
  const { nome, tipo, login, senha } = req.body;
  if (!nome || !tipo || !login || !senha || tipo === 'admin') return res.status(400).json({ error: 'Dados inválidos' });
  const hashed = await bcrypt.hash(senha, BCRYPT_ROUNDS);
  db.run("INSERT INTO usuarios (nome, tipo, login, senha) VALUES (?, ?, ?, ?)", [nome, tipo, login, hashed], (err) => {
      if (err) return res.status(400).json({ error: 'Login já existe' });
      res.json({ message: 'Usuário cadastrado' });
  });
});
app.post('/api/login', (req, res) => {
  const { login, senha } = req.body;
  db.get("SELECT * FROM usuarios WHERE login = ?", [login], async (err, user) => {
    if (!user || !(await bcrypt.compare(senha, user.senha))) {
      return res.status(401).json({ error: 'Credenciais incorretas' });
    }
    req.session.user = { id: user.id, nome: user.nome, tipo: user.tipo };
    res.json({ user: req.session.user });
  });
});
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get('/api/session', (req, res) => {
  if (req.session && req.session.user) return res.json({ user: req.session.user });
  res.status(401).json({ error: 'Não autenticado' });
});
app.get('/api/despachantes', (req, res) => {
  db.all("SELECT id, nome FROM usuarios WHERE tipo = 'despachante'", [], (err, rows) => res.json({ despachantes: rows || [] }));
});
app.get('/api/pendencias', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Não autenticado' });
  const userId = req.session.user.id;
  db.all(
    `SELECT p.*, u.nome as criador_nome, d.nome as despachante_nome FROM pendencias p JOIN usuarios u ON p.criador_id = u.id JOIN usuarios d ON p.despachante_id = d.id WHERE p.criador_id = ? OR p.despachante_id = ? ORDER BY p.criado_em DESC`,
    [userId, userId],
    (err, rows) => res.json({ pendencias: rows || [] })
  );
});
app.post('/api/pendencias', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Não autenticado' });
  const { placa, descricao, despachante_id } = req.body;
  const criador_id = req.session.user.id;
  db.run("INSERT INTO pendencias (placa, descricao, criador_id, despachante_id, status, criado_em) VALUES (?, ?, ?, ?, 'pendente', CURRENT_TIMESTAMP)", 
    [placa, descricao || '', criador_id, despachante_id], 
    () => res.json({ message: 'Pendência criada' })
  );
});
app.get('/api/admin/users', isAdmin, (req, res) => {
    db.all("SELECT id, nome, tipo, login FROM usuarios", [], (err, rows) => res.json(rows || []));
});
app.put('/api/admin/users/:id', isAdmin, async (req, res) => {
    const { nome, tipo, login, senha } = req.body;
    if (senha) {
        const hashed = await bcrypt.hash(senha, BCRYPT_ROUNDS);
        db.run("UPDATE usuarios SET nome=?, tipo=?, login=?, senha=? WHERE id=?", [nome, tipo, login, hashed, req.params.id]);
    } else {
        db.run("UPDATE usuarios SET nome=?, tipo=?, login=? WHERE id=?", [nome, tipo, login, req.params.id]);
    }
    res.json({ message: 'Usuário atualizado' });
});
app.delete('/api/admin/users/:id', isAdmin, (req, res) => {
    if (req.session.user.id == req.params.id) return res.status(400).json({ error: 'Não pode deletar a si mesmo' });
    db.run("DELETE FROM usuarios WHERE id = ?", [req.params.id], () => res.json({ message: 'Usuário deletado' }));
});
app.get('/api/admin/pendencias', isAdmin, (req, res) => {
    db.all(
        `SELECT p.*, u_criador.nome as criador_nome, u_despachante.nome as despachante_nome
        FROM pendencias p
        LEFT JOIN usuarios u_criador ON p.criador_id = u_criador.id
        LEFT JOIN usuarios u_despachante ON p.despachante_id = u_despachante.id
        ORDER BY p.criado_em DESC`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Erro DB' });
            res.json(rows || []);
        }
    );
});
app.put('/api/admin/pendencias/:id', isAdmin, (req, res) => {
    const { placa, descricao, status } = req.body;
    db.run("UPDATE pendencias SET placa = ?, descricao = ?, status = ? WHERE id = ?", 
        [placa, descricao, status, req.params.id], 
        (err) => {
            if (err) return res.status(500).json({ error: 'Erro ao atualizar pendência' });
            res.json({ message: 'Pendência atualizada com sucesso.' });
        }
    );
});
app.delete('/api/admin/pendencias/:id', isAdmin, (req, res) => {
    db.run("DELETE FROM pendencias WHERE id = ?", [req.params.id], () => res.json({ message: 'Pendência deletada' }));
});

// --- Static File Server ---
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- WebSocket Server ---
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });
const clientsByUserId = new Map();

function broadcastUpdate() {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && client.session.user) {
            const userId = client.session.user.id;
            db.all(
                `SELECT p.*, u.nome as criador_nome, d.nome as despachante_nome FROM pendencias p JOIN usuarios u ON p.criador_id = u.id JOIN usuarios d ON p.despachante_id = d.id WHERE p.criador_id = ? OR p.despachante_id = ? ORDER BY p.criado_em DESC`,
                [userId, userId],
                (err, rows) => {
                    if(rows) client.send(JSON.stringify({ type: 'update', pendencias: rows }));
                }
            );
        }
    });
}
db.on('change', broadcastUpdate);

server.on('upgrade', (request, socket, head) => {
  sessionParser(request, {}, () => {
    if (!request.session.user) return socket.destroy();
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

  ws.on('message', (message) => {
    const msg = JSON.parse(message.toString());
    const { type, pendenciaId } = msg;
    if (!type || !pendenciaId || (type !== 'resolver' && type !== 'pendente')) return;

    db.get("SELECT * FROM pendencias WHERE id = ?", [pendenciaId], (err, pendencia) => {
        if (!pendencia) return;
        const lastUpdate = type === 'resolver' ? pendencia.criado_em : pendencia.resolvido_em;
        if (!isSameDay(lastUpdate)) {
            return ws.send(JSON.stringify({ type: 'error', message: 'Alteração permitida apenas no mesmo dia.' }));
        }
        const sql = type === 'resolver'
            ? "UPDATE pendencias SET status = 'resolvido', resolvido_em = CURRENT_TIMESTAMP WHERE id = ?"
            : "UPDATE pendencias SET status = 'pendente', resolvido_em = NULL WHERE id = ?";
        db.run(sql, [pendenciaId]);
    });
  });

  ws.on('close', () => clientsByUserId.delete(String(user.id)));
});

// --- Server Listen ---
server.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
