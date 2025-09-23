import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
// Removed database usage; using in-memory store instead
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import nodemailer from 'nodemailer';
import { stringify } from 'csv-stringify';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const ADMIN_PASS = process.env.ADMIN_PASS || '12041998avril1999A';

// In-memory stores (non-persistent; resets on server restart)
const memory = {
  users: new Map(), // username -> { username, email, password_hash, balances, banned, withdraw_code_hash }
  chats: new Map(), // username -> [ { from, text, time } ]
  emailTokens: new Map(), // username -> token
  transactions: [], // { username, type, pair, amount, currency, value_eur, created_at }
};


// Ensure admin exists in users table (admin credentials come from ADMIN_PASS env)
async function ensureAdminUser(){
  const existing = memory.users.get('admin');
  if(!existing){
    memory.users.set('admin', { username:'admin', email:'admin@localhost', password_hash: await bcrypt.hash(ADMIN_PASS, 12), balances:{ EUR:0, BTC:0, ETH:0, USDT:0 }, banned:false });
    memory.chats.set('admin', []);
  }
  console.log('✅ Admin user ensured (in-memory)');
}

ensureAdminUser().catch(e=>{ console.error('admin init failed', e); process.exit(1); });


const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true } });

app.use(cors());
app.use(express.json());
app.use(helmet());

// Rate limiting - basic
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use('/api/', apiLimiter);

// CORS - restrict via ENV (comma-separated origin list) if provided
const allowed = (process.env.CORS_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
if(allowed.length) app.use(cors({ origin: allowed }));
else app.use(cors());

// Nodemailer transporter (optional)
let transporter = null;
if(process.env.SMTP_HOST){
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: (process.env.SMTP_SECURE === 'true'),
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  });
}

app.use(express.static(path.join(__dirname, 'public')));

// Market simulation
const PAIRS = {
  'BTC/EUR': { symbol:'BTC', price:25000, vol:0.03 },
  'ETH/EUR': { symbol:'ETH', price:1500, vol:0.04 },
  'USDT/EUR': { symbol:'USDT', price:1, vol:0.001 }
};
const priceSeries = {};
Object.keys(PAIRS).forEach(k=>priceSeries[k]=[PAIRS[k].price]);
function stepMarket(){
  Object.keys(PAIRS).forEach(pair=>{
    const meta = PAIRS[pair];
    const last = priceSeries[pair][priceSeries[pair].length-1];
    const shock = (Math.random()-0.5)*2*meta.vol;
    const drift = (Math.random()-0.5)*0.001;
    const next = Math.max(0.00001, last*(1+shock+drift));
    priceSeries[pair].push(next);
    if(priceSeries[pair].length>300) priceSeries[pair].shift();
  });
  io.emit('prices', currentPrices());
}
setInterval(stepMarket, 1000);
function currentPrices(){ const out={}; for(const p in priceSeries) out[p]=priceSeries[p][priceSeries[p].length-1]; return out; }

// Helpers
function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({ error:'no auth' });
  const token = h.split(' ')[1];
  try{ const payload = jwt.verify(token, JWT_SECRET); req.user = payload; next(); }catch(e){ return res.status(401).json({ error:'invalid token' }); }
}

async function getUserRow(username){
  const u = memory.users.get(username);
  if(!u) return null;
  return { username: u.username, email: u.email, balances: u.balances, banned: !!u.banned };
}

// Routes
app.get('/health', (req,res)=> res.json({ status:'ok', uptime: process.uptime() }));

app.post('/api/register', [
  body('username').isLength({ min:3, max:40 }).matches(/^[a-zA-Z0-9_\-]+$/),
  body('email').isEmail(),
  body('password').isLength({ min:8 })
], async (req,res)=>{ const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ error:'validation', details: errors.array() });
  const { username, email, password } = req.body;
  if(!username || !email || !password) return res.status(400).json({ error:'missing' });
  if(username === 'admin') return res.status(400).json({ error:'invalid username' });
  try{
    const hash = await bcrypt.hash(password, 10);
    if(memory.users.has(username)) return res.status(400).json({ error:'user exists' });
    memory.users.set(username, { username, email, password_hash: hash, balances:{ EUR:0, BTC:0, ETH:0, USDT:0 }, banned:false });
    if(!memory.chats.has(username)) memory.chats.set(username, []);
    // create email verification token (logged if no SMTP)
    const verToken = (await import('crypto')).randomBytes(20).toString('hex');
    memory.emailTokens.set(username, verToken);
    // send email if transporter configured, otherwise log verification link
    const verifyLink = (process.env.BASE_URL || '') + '/verify-email?username=' + encodeURIComponent(username) + '&token=' + verToken;
    if(transporter){
      transporter.sendMail({ from: process.env.SMTP_FROM || 'no-reply@example.com', to: email, subject: 'Verify your trading bot account', text: 'Verify your account: ' + verifyLink, html: '<p>Click to verify: <a href="'+verifyLink+'">Verify email</a></p>' }).catch(e=>console.error('mail err', e));
    } else { console.log('VERIFICATION LINK:', verifyLink); }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user: { username, email, verifySent: true } });
  }catch(err){
    console.error('register err', err);
    res.status(400).json({ error:'register failed' });
  }
});

app.post('/api/login', [ body('username').notEmpty(), body('password').notEmpty() ], async (req,res)=>{ const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ error:'validation' });
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ error:'missing' });
  if(username === 'admin'){
    if(password !== ADMIN_PASS) return res.status(401).json({ error:'invalid' });
    const token = jwt.sign({ username:'admin', admin:true }, JWT_SECRET, { expiresIn:'7d' });
    return res.json({ token, user:{ username:'admin', admin:true } });
  }
  try{
    const row = memory.users.get(username);
    if(!row) return res.status(401).json({ error:'invalid' });
    if(row.banned) return res.status(403).json({ error:'banned' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if(!ok) return res.status(401).json({ error:'invalid' });
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user: { username: row.username, email: row.email, balances: row.balances } });
  }catch(e){ console.error('login err', e); res.status(500).json({ error:'server' }); }
});

// Admin endpoints
app.get('/api/admin/users', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const rows = Array.from(memory.users.values()).map(u=>({ username:u.username, email:u.email, balances:u.balances, banned:!!u.banned }))
    .sort((a,b)=> a.username.localeCompare(b.username));
  res.json(rows);
});

// Admin set balance (manual only)
app.post('/api/admin/set-balance', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const { username, currency, amount } = req.body;
  if(!username || !currency || typeof amount !== 'number') return res.status(400).json({ error:'missing' });
  const user = memory.users.get(username);
  if(!user) return res.status(404).json({ error:'not found' });
  const balances = user.balances || { EUR:0 };
  balances[currency] = amount;
  user.balances = balances;
  memory.transactions.push({ username, type:'admin-adjust', pair:null, amount, currency, value_eur:null, created_at:new Date(), note:'admin set balance' });
  // notify via sockets and append chat
  io.to(username).emit('balance_updated', { username, balances });
  let msgs = memory.chats.get(username) || [];
  msgs.push({ from:'admin', text:`Your ${currency} balance set to ${amount}`, time: new Date() });
  memory.chats.set(username, msgs);
  io.to(username).emit('chat_message', { user: username, from:'admin', text:`Your ${currency} balance set to ${amount}`, time: new Date() });
  res.json({ ok:true });
});

// Admin ban/unban
app.post('/api/admin/ban', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const { username, ban } = req.body;
  if(!username || typeof ban !== 'boolean') return res.status(400).json({ error:'missing' });
  const user = memory.users.get(username);
  if(user){ user.banned = ban; }
  io.to(username).emit('banned', { banned: ban, message: ban ? 'You have been banned by admin.' : 'You have been unbanned.' });
  res.json({ ok:true });
});

// Admin fetch chat history
app.get('/api/admin/chat/:username', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const username = req.params.username;
  const msgs = memory.chats.get(username) || [];
  res.json(msgs);
});

// Export transactions
app.get('/api/transactions/export', authMiddleware, async (req,res)=>{
  const requester = req.user.username;
  const username = req.query.username;
  let rows = memory.transactions;
  if(requester !== 'admin') rows = rows.filter(t=>t.username===requester);
  else if(username) rows = rows.filter(t=>t.username===username);
  const records = rows.map(t=>({ username: t.username, type: t.type, pair: t.pair, amount: t.amount, currency: t.currency, valueEUR: t.value_eur, timestamp: t.created_at }));
  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="transactions_${username||'all'}.csv"`);
  stringify(records, { header:true }).pipe(res);
});

app.get('/api/prices', (req,res)=> res.json(currentPrices()));




// Withdraw request endpoint - simplified (no withdrawCode in vanilla mode)
app.post('/api/withdraw', authMiddleware, async (req,res)=>{
  const { amount, currency } = req.body;
  if(!amount || !currency) return res.status(400).json({ error:'missing fields' });
  try{
    const msg = { from: req.user.username, text: `Withdrawal request: ${amount} ${currency}`, time: new Date() };
    const msgs = memory.chats.get(req.user.username) || [];
    msgs.push(msg);
    memory.chats.set(req.user.username, msgs);
    io.to('admins').emit('chat_message', { user: req.user.username, from: req.user.username, text: msg.text, time: msg.time });
    res.json({ success:true, message:'Withdrawal request sent to admin' });
  }catch(e){ console.error('withdraw err', e); res.status(500).json({ error:'server error' }); }
});


// Email verification endpoint (simple GET used from email link)
app.get('/verify-email', async (req,res)=>{
  const username = req.query.username;
  const token = req.query.token;
  if(!username || !token) return res.status(400).send('missing');
  const saved = memory.emailTokens.get(username);
  if(!saved || saved !== token) return res.status(400).send('invalid or expired token');
  memory.emailTokens.delete(username);
  res.send('Email verified for ' + username + '. You can now use the app.');
});


// Chat & sockets
io.on('connection', socket => {
  socket.on('auth', async ({ token })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      socket.user = p;
      if(p.username === 'admin'){
        socket.join('admins');
        socket.emit('prices', currentPrices());
      } else {
        socket.join(p.username);
        const u = memory.users.get(p.username);
        const balances = u ? (u.balances || { EUR:0 }) : { EUR:0 };
        socket.emit('auth_ok', { user: { username: p.username, balances } });
        const msgs = memory.chats.get(p.username) || [];
        socket.emit('chat_history', msgs);
      }
    }catch(e){ socket.emit('auth_error', { msg:'invalid token' }); }
  });

  socket.on('send_chat', async ({ token, text })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      const username = p.username;
      let msgs = memory.chats.get(username) || [];
      msgs.push({ from: username, text, time: new Date() });
      memory.chats.set(username, msgs);
      // notify admin and user
      io.to('admins').emit('chat_message', { user: username, from: username, text, time: new Date() });
      io.to(username).emit('chat_message', { user: username, from: username, text, time: new Date() });
    }catch(e){ console.error('send_chat err', e); }
  });

  socket.on('admin_reply', async ({ token, username, text })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      if(p.username !== 'admin') return;
      let msgs = memory.chats.get(username) || [];
      msgs.push({ from: 'admin', text, time: new Date() });
      memory.chats.set(username, msgs);
      io.to(username).emit('chat_message', { user: username, from: 'admin', text, time: new Date() });
      io.to('admins').emit('chat_message', { user: username, from: 'admin', text, time: new Date() });
    }catch(e){ console.error('admin_reply err', e); }
  });

  socket.on('trade', async ({ token, pair, type, amountBase })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      const username = p.username;
      const u = memory.users.get(username);
      if(!u) return socket.emit('trade_result', { ok:false, reason:'user not found' });
      if(u.banned) return socket.emit('trade_result', { ok:false, reason:'banned' });
      const balances = u.balances || { EUR:0 };
      const price = currentPrices()[pair];
      const sym = PAIRS[pair].symbol;
      if(type === 'buy'){
        const cost = Number(amountBase) * Number(price);
        if((balances.EUR||0) < cost) return socket.emit('trade_result', { ok:false, reason:'insufficient EUR' });
        balances.EUR = (balances.EUR||0) - cost;
        balances[sym] = (balances[sym]||0) + Number(amountBase);
        u.balances = balances;
        memory.transactions.push({ username, type:'buy', pair, amount:amountBase, currency:sym, value_eur:cost, created_at:new Date() });
      } else {
        if((balances[sym]||0) < Number(amountBase)) return socket.emit('trade_result', { ok:false, reason:'insufficient asset' });
        balances[sym] = (balances[sym]||0) - Number(amountBase);
        const proceeds = Number(amountBase) * Number(price);
        balances.EUR = (balances.EUR||0) + proceeds;
        u.balances = balances;
        memory.transactions.push({ username, type:'sell', pair, amount:amountBase, currency:sym, value_eur:proceeds, created_at:new Date() });
      }
      io.to(username).emit('trade_result', { ok:true, balances });
      io.to('admins').emit('user_update', { username, balances });
    }catch(e){ console.error('trade err', e); socket.emit('trade_result', { ok:false, reason:'server' }); }
  });

  socket.on('disconnect', ()=>{});
});

// SPA fallback
app.get('/', (req,res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('*', (req,res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

server.listen(PORT, ()=> console.log('Persistent trading bot server started on', PORT));