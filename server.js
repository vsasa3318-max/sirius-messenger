const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean), methods: ['GET', 'POST'] } });
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === 'production' ? '' : 'local-dev-only-change-this-secret');
if (!SECRET || SECRET.length < 24) {
  console.error('Set JWT_SECRET to a random secret of at least 24 characters.');
  process.exit(1);
}
const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const uploadDir = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'));
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(dataDir, 'sirius.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL COLLATE NOCASE UNIQUE,
 email TEXT NOT NULL COLLATE NOCASE UNIQUE,
 password_hash TEXT NOT NULL,
 bio TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS chats (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 is_group INTEGER NOT NULL DEFAULT 0,
 created_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS chat_members (
 chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 joined_at TEXT NOT NULL DEFAULT (datetime('now')),
 PRIMARY KEY(chat_id, user_id)
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
 sender_id INTEGER NOT NULL REFERENCES users(id),
 body TEXT NOT NULL DEFAULT '',
 attachment_name TEXT,
 attachment_path TEXT,
 attachment_type TEXT,
 attachment_size INTEGER,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id, id);
CREATE INDEX IF NOT EXISTS idx_members_user ON chat_members(user_id);
`);
// Safe in-place migration for databases created by earlier project versions.
const userColumns = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
if (!userColumns.includes('status')) db.exec("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT ''");
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin(origin, callback) {
  if (!origin) return callback(null, false);
  return callback(null, allowedOrigins.includes(origin));
} }));
app.use(express.json({ limit: '1mb' }));
const authAttempts = new Map();
app.use('/api/auth', (req, res, next) => {
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = authAttempts.get(key) || { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 15 * 60 * 1000; }
  entry.count += 1; authAttempts.set(key, entry);
  if (entry.count > 30) return res.status(429).json({ error: 'Слишком много попыток. Попробуй позже.' });
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

const safeUser = u => ({ id: u.id, username: u.username, email: u.email, bio: u.bio || '', status: u.status || '', createdAt: u.created_at });
function sign(user) { return jwt.sign({ id: user.id }, SECRET, { expiresIn: '7d', issuer: 'sirius' }); }
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    const decoded = jwt.verify(token, SECRET, { issuer: 'sirius' });
    const user = db.prepare('SELECT id, username, email, bio, status, created_at FROM users WHERE id = ?').get(decoded.id);
    if (!user) return res.status(401).json({ error: 'Сессия завершена. Войди снова.' });
    req.user = user; next();
  } catch { return res.status(401).json({ error: 'Нужен вход в аккаунт.' }); }
}
function memberOf(chatId, userId) {
  return !!db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, userId);
}
function chatSummary(chatId, userId) {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  if (!chat || !memberOf(chatId, userId)) return null;
  const members = db.prepare(`SELECT u.id, u.username FROM users u JOIN chat_members cm ON cm.user_id=u.id WHERE cm.chat_id=? ORDER BY u.username`).all(chatId);
  const last = db.prepare(`SELECT m.id,m.body,m.attachment_name,m.created_at,u.username AS sender_name
    FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.chat_id=? ORDER BY m.id DESC LIMIT 1`).get(chatId);
  let title = chat.title;
  if (!chat.is_group) {
    const other = members.find(m => m.id !== userId);
    title = other ? other.username : 'Избранное';
  }
  return { id: chat.id, title, isGroup: !!chat.is_group, members, lastMessage: last || null, createdAt: chat.created_at };
}
function serializeMessage(row, viewerId) {
  const file = row.attachment_path ? path.basename(row.attachment_path) : null;
  const fileToken = file ? jwt.sign({ id: viewerId, file }, SECRET, { expiresIn: '10m', issuer: 'sirius-files' }) : null;
  return { id: row.id, chatId: row.chat_id, body: row.body, sender: { id: row.sender_id, username: row.username },
    attachment: row.attachment_name ? { name: row.attachment_name, url: `/uploads/${encodeURIComponent(file)}?t=${encodeURIComponent(fileToken)}`, type: row.attachment_type, size: row.attachment_size } : null,
    createdAt: row.created_at };
}
function messageById(id) {
  return db.prepare(`SELECT m.*, u.username FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?`).get(id);
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'SIRIUS', time: new Date().toISOString() }));

app.post('/api/auth/register', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(username)) return res.status(400).json({ error: 'Имя должно быть длиной 3–24 символа: латиница, цифры, точка, дефис или подчёркивание.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return res.status(400).json({ error: 'Укажи корректную почту.' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Пароль должен содержать 8–128 символов.' });
  if (db.prepare('SELECT id FROM users WHERE email=? OR username=?').get(email, username)) return res.status(409).json({ error: 'Эта почта или имя уже заняты.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users(username,email,password_hash) VALUES(?,?,?)').run(username, email, hash);
    const user = db.prepare('SELECT id,username,email,bio,created_at FROM users WHERE id=?').get(result.lastInsertRowid);
    res.status(201).json({ token: sign(user), user: safeUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Не удалось создать аккаунт.' }); }
});
app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Неверная почта или пароль.' });
  res.json({ token: sign(user), user: safeUser(user) });
});
app.get('/api/me', auth, (req, res) => res.json({ user: safeUser(req.user) }));
app.patch('/api/me', auth, (req, res) => {
  const bio = String(req.body.bio || '').trim().slice(0, 180);
  const status = String(req.body.status || '').trim().slice(0, 60);
  db.prepare('UPDATE users SET bio=?, status=? WHERE id=?').run(bio, status, req.user.id);
  res.json({ user: safeUser(db.prepare('SELECT id,username,email,bio,status,created_at FROM users WHERE id=?').get(req.user.id)) });
});
app.get('/api/users', auth, (req, res) => {
  const q = String(req.query.q || '').trim().replace(/^@/, '').slice(0, 40);
  if (q.length < 2) return res.json({ users: [] });
  const users = db.prepare(`SELECT id,username,bio,status FROM users WHERE id != ? AND username LIKE ? ESCAPE '\\' ORDER BY username LIMIT 20`)
    .all(req.user.id, `%${q.replace(/[\\%_]/g, '\\$&')}%`);
  res.json({ users });
});
app.get('/api/chats', auth, (req, res) => {
  const ids = db.prepare('SELECT chat_id FROM chat_members WHERE user_id=?').all(req.user.id);
  res.json({ chats: ids.map(x => chatSummary(x.chat_id, req.user.id)).filter(Boolean).sort((a,b) => {
    const da = a.lastMessage?.created_at || a.createdAt, dbb = b.lastMessage?.created_at || b.createdAt;
    return String(dbb).localeCompare(String(da));
  }) });
});
app.post('/api/chats/direct', auth, (req, res) => {
  const otherId = Number(req.body.userId);
  if (!Number.isInteger(otherId) || otherId === req.user.id || !db.prepare('SELECT id FROM users WHERE id=?').get(otherId)) return res.status(400).json({ error: 'Пользователь не найден.' });
  const existing = db.prepare(`SELECT c.id FROM chats c JOIN chat_members a ON a.chat_id=c.id AND a.user_id=? JOIN chat_members b ON b.chat_id=c.id AND b.user_id=? WHERE c.is_group=0 LIMIT 1`).get(req.user.id, otherId);
  if (existing) return res.json({ chat: chatSummary(existing.id, req.user.id) });
  const create = db.transaction(() => {
    const r = db.prepare('INSERT INTO chats(title,is_group,created_by) VALUES(?,0,?)').run('Диалог', req.user.id);
    db.prepare('INSERT INTO chat_members(chat_id,user_id) VALUES(?,?),(?,?)').run(r.lastInsertRowid, req.user.id, r.lastInsertRowid, otherId);
    return r.lastInsertRowid;
  });
  const id = create();
  io.to(`user:${otherId}`).emit('chats:changed');
  res.status(201).json({ chat: chatSummary(id, req.user.id) });
});
app.post('/api/chats/group', auth, (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 60);
  const ids = [...new Set((Array.isArray(req.body.userIds) ? req.body.userIds : []).map(Number).filter(id => Number.isInteger(id) && id !== req.user.id))];
  if (title.length < 2) return res.status(400).json({ error: 'Название группы должно быть не короче 2 символов.' });
  if (ids.length < 1 || ids.length > 49) return res.status(400).json({ error: 'Выбери от 1 до 49 участников.' });
  const valid = db.prepare(`SELECT id FROM users WHERE id IN (${ids.map(()=>'?').join(',')})`).all(...ids);
  if (valid.length !== ids.length) return res.status(400).json({ error: 'Некоторые пользователи не найдены.' });
  const create = db.transaction(() => {
    const r = db.prepare('INSERT INTO chats(title,is_group,created_by) VALUES(?,1,?)').run(title, req.user.id);
    const add = db.prepare('INSERT INTO chat_members(chat_id,user_id) VALUES(?,?)');
    add.run(r.lastInsertRowid, req.user.id); ids.forEach(id => add.run(r.lastInsertRowid, id));
    return r.lastInsertRowid;
  });
  const id = create();
  ids.forEach(uid => io.to(`user:${uid}`).emit('chats:changed'));
  res.status(201).json({ chat: chatSummary(id, req.user.id) });
});
app.get('/api/chats/:id/messages', auth, (req, res) => {
  const chatId = Number(req.params.id);
  if (!memberOf(chatId, req.user.id)) return res.status(403).json({ error: 'Нет доступа к этому чату.' });
  const before = Number(req.query.before || Number.MAX_SAFE_INTEGER);
  const rows = db.prepare(`SELECT m.*,u.username FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.chat_id=? AND m.id<? ORDER BY m.id DESC LIMIT 100`).all(chatId, before);
  res.json({ messages: rows.reverse().map(row => serializeMessage(row, req.user.id)) });
});
const allowedMime = new Set(['image/jpeg','image/png','image/gif','image/webp','application/pdf','text/plain','application/zip','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']);
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).slice(0, 12))
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (_req, file, cb) => {
  if (!allowedMime.has(file.mimetype)) return cb(new Error('Этот тип файла не разрешён.'));
  cb(null, true);
}});
app.post('/api/chats/:id/messages', auth, upload.single('file'), (req, res) => {
  const chatId = Number(req.params.id);
  if (!memberOf(chatId, req.user.id)) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(403).json({ error: 'Нет доступа к этому чату.' });
  }
  const body = String(req.body.body || '').trim().slice(0, 4000);
  if (!body && !req.file) return res.status(400).json({ error: 'Напиши сообщение или прикрепи файл.' });
  const result = db.prepare(`INSERT INTO messages(chat_id,sender_id,body,attachment_name,attachment_path,attachment_type,attachment_size) VALUES(?,?,?,?,?,?,?)`)
    .run(chatId, req.user.id, body, req.file ? path.basename(req.file.originalname).slice(0,180) : null, req.file ? req.file.filename : null, req.file ? req.file.mimetype : null, req.file ? req.file.size : null);
  const message = serializeMessage(messageById(result.lastInsertRowid), req.user.id);
  io.to(`chat:${chatId}`).emit('message:new', message);
  db.prepare('SELECT user_id FROM chat_members WHERE chat_id=? AND user_id != ?').all(chatId, req.user.id).forEach(row => io.to(`user:${row.user_id}`).emit('chats:changed'));
  res.status(201).json({ message });
});
app.use('/uploads', (req, res, next) => {
  // Short-lived signed URLs allow native img/link requests without exposing account JWTs.
  const file = path.basename(decodeURIComponent(req.path));
  try {
    const payload = jwt.verify(String(req.query.t || ''), SECRET, { issuer: 'sirius-files' });
    const row = db.prepare('SELECT chat_id FROM messages WHERE attachment_path=?').get(file);
    if (payload.file !== file || !row || !memberOf(row.chat_id, payload.id)) return res.status(403).end('Нет доступа');
    next();
  } catch { return res.status(403).end('Ссылка на файл устарела. Обнови чат.'); }
}, express.static(uploadDir, { fallthrough: false }));
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Максимальный размер файла — 10 МБ.' });
  if (err) return res.status(400).json({ error: err.message || 'Ошибка запроса.' });
  res.status(500).json({ error: 'Внутренняя ошибка.' });
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    const decoded = jwt.verify(token, SECRET, { issuer: 'sirius' });
    const user = db.prepare('SELECT id,username FROM users WHERE id=?').get(decoded.id);
    if (!user) return next(new Error('Нужен вход'));
    socket.user = user; next();
  } catch { next(new Error('Нужен вход')); }
});
io.on('connection', socket => {
  const uid = socket.user.id;
  socket.join(`user:${uid}`);
  db.prepare('SELECT chat_id FROM chat_members WHERE user_id=?').all(uid).forEach(row => socket.join(`chat:${row.chat_id}`));
  socket.on('chats:sync', () => {
    db.prepare('SELECT chat_id FROM chat_members WHERE user_id=?').all(uid).forEach(row => socket.join(`chat:${row.chat_id}`));
  });
  socket.on('chat:join', chatId => {
    const id = Number(chatId);
    if (memberOf(id, uid)) socket.join(`chat:${id}`);
  });
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
server.listen(PORT, '0.0.0.0', () => console.log(`SIRIUS listening on ${PORT}`));
