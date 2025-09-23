// app.js for persistent trading bot - handles login/register, dashboard, admin UI, sockets, chart
const API = '';

function $(id){return document.getElementById(id);}
function fmtEUR(n){return '€'+Number(n||0).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2});}

let token = localStorage.getItem('token');
let socket = null;
let latestPrices = {};
let chartData = { 'BTC/EUR':[], 'ETH/EUR':[], 'USDT/EUR':[] };
let chartMaxPoints = 100;

if(location.pathname.endsWith('/index.html') || location.pathname === '/' ){ initIndex(); } else if(location.pathname.endsWith('dashboard.html')){ initDashboard(); } else if(location.pathname.endsWith('admin.html')){ initAdmin(); }

function initIndex(){
  const loginForm = $('login-form'), regForm = $('register-form');
  $('show-register').addEventListener('click', e=>{ e.preventDefault(); loginForm.classList.add('hidden'); regForm.classList.remove('hidden'); });
  $('show-login').addEventListener('click', e=>{ e.preventDefault(); regForm.classList.add('hidden'); loginForm.classList.remove('hidden'); });

  $('reg-btn').addEventListener('click', async ()=>{
    const u=$('reg-username').value.trim(), e=$('reg-email').value.trim(), p=$('reg-password').value;
    if(!u||!e||!p) return alert('fill all');
    const res = await fetch('/api/register',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username:u, email:e, password:p }) });
    const j = await res.json();
    if(j.token){ localStorage.setItem('token', j.token); location.href='dashboard.html'; } else alert('Error: '+(j.error||'unknown'));
  });

  $('login-btn').addEventListener('click', async ()=>{
    const u=$('login-username').value.trim(), p=$('login-password').value;
    if(!u||!p) return alert('fill both');
    const res = await fetch('/api/login',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username:u, password:p }) });
    const j = await res.json();
    if(j.token){ localStorage.setItem('token', j.token); if(j.user && j.user.admin) location.href='admin.html'; else location.href='dashboard.html'; } else alert('Login failed: '+(j.error||'unknown'));
  });
}

function connectSocket(){
  if(socket) socket.disconnect();
  socket = io();
  socket.on('connect', ()=>{ if(localStorage.getItem('token')) socket.emit('auth', { token: localStorage.getItem('token') }); });
  socket.on('auth_ok', ({ user })=>{ renderWallet(user); fetchPrices(); });
  socket.on('chat_history', msgs=>{ renderChat(msgs); });
  socket.on('chat_message', m=>{ appendChat(m); });
  socket.on('prices', p=>{ latestPrices = p; updateChart(p); renderPrice(p); });
  socket.on('balance_updated', d=>{ if(location.pathname.endsWith('dashboard.html')) fetchMe(); });
  socket.on('trade_result', r=>{ if(r.ok){ fetchMe(); alert('Trade done'); } else alert('Trade failed: '+(r.reason||'error')); });
  socket.on('banned', ()=>{ alert('You were banned'); localStorage.removeItem('token'); location.href='/'; });
  socket.on('user_update', ()=>{ if(location.pathname.endsWith('admin.html')) fetchUsers(); });
}

async function fetchMe(){ const res = await fetch('/api/admin/users', { headers:{ Authorization:'Bearer '+localStorage.getItem('token') } }); if(res.ok){ const arr = await res.json(); const me = arr.find(x=>x.username===getUser()); if(me) renderWallet(me); } }

function renderWallet(user){ const w=$('wallet'); if(!w) return; w.innerHTML=''; const b = user.balances||{}; let total=0; for(const k of Object.keys(b)){ const v=b[k]||0; const el=document.createElement('div'); el.textContent = `${k}: ${v}`; w.appendChild(el); if(k==='EUR') total+=v; else { const pair = `${k}/EUR`; const rate = latestPrices[pair]||0; total += v * rate; } } $('total-eur').textContent = fmtEUR(total); }

function updateChart(prices){ for(const p in prices){ const arr = chartData[p] || []; arr.push(Number(prices[p])); if(arr.length>chartMaxPoints) arr.shift(); chartData[p]=arr; } drawChart(); }
function drawChart(){ const pair = $('pair-select') ? $('pair-select').value : 'BTC/EUR'; const data = chartData[pair] || []; const c = $('chart'); if(!c) return; const ctx=c.getContext('2d'); ctx.clearRect(0,0,c.width,c.height); if(data.length<2) return; const w=c.width, h=c.height, len=data.length; const max=Math.max(...data), min=Math.min(...data); ctx.beginPath(); for(let i=0;i<len;i++){ const x = (i/(len-1))* (w-10) +5; const y = h-10 - ((data[i]-min)/(max-min || 1))*(h-20); if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y); } ctx.strokeStyle='#7dd3fc'; ctx.lineWidth=2; ctx.stroke(); }

function renderPrice(prices){ const p = prices && prices[$('pair-select')?.value] ? prices[$('pair-select').value] : 0; const el = $('price'); if(el) el.textContent = fmtEUR(p); }
function renderChat(msgs){ const el=$('chat-history'); if(!el) return; el.innerHTML=''; (msgs||[]).forEach(m=>{ const d=document.createElement('div'); d.textContent = `${m.from}: ${m.text}`; el.appendChild(d); }); el.scrollTop = el.scrollHeight; }
function appendChat(m){ const el=$('chat-history')||$('admin-chat-history'); if(!el) return; const d=document.createElement('div'); const who = m.from || m.user; d.textContent = `${who}: ${m.text}`; el.appendChild(d); el.scrollTop = el.scrollHeight; }
function getUser(){ try{ const t = localStorage.getItem('token'); if(!t) return null; return JSON.parse(atob(t.split('.')[1])).username; }catch(e){ return null; } }

function initDashboard(){ if(!localStorage.getItem('token')) return location.href='/'; connectSocket(); $('logout').addEventListener('click', ()=>{ localStorage.removeItem('token'); location.href='/'; }); $('chat-send').addEventListener('click', ()=>{ const text=$('chat-input').value.trim(); if(!text) return; socket.emit('send_chat',{ token: localStorage.getItem('token'), text }); $('chat-input').value=''; }); $('buy').addEventListener('click', ()=>{ const amt=Number($('trade-amount').value)||0; socket.emit('trade',{ token: localStorage.getItem('token'), pair: $('pair-select').value, type:'buy', amountBase: amt }); }); $('sell').addEventListener('click', ()=>{ const amt=Number($('trade-amount').value)||0; socket.emit('trade',{ token: localStorage.getItem('token'), pair: $('pair-select').value, type:'sell', amountBase: amt }); }); $('pair-select').addEventListener('change', ()=> drawChart()); setTimeout(fetchMe, 300); }

function initAdmin(){ if(!localStorage.getItem('token')) return location.href='/'; connectSocket(); $('admin-logout').addEventListener('click', ()=>{ localStorage.removeItem('token'); location.href='/'; }); $('admin-chat-send').addEventListener('click', ()=>{ const text=$('admin-chat-input').value.trim(); const user = prompt('Reply to username:'); if(!user||!text) return; socket.emit('admin_reply',{ token: localStorage.getItem('token'), username: user, text }); $('admin-chat-input').value=''; fetchUsers(); }); $('export-all').addEventListener('click', ()=>{ window.open('/api/transactions/export', '_blank'); }); fetchUsers(); setInterval(fetchUsers, 2000); }

async function fetchUsers(){ const res = await fetch('/api/admin/users', { headers:{ Authorization:'Bearer '+localStorage.getItem('token') } }); if(!res.ok) return; const arr = await res.json(); const tbody = $('users-table').querySelector('tbody'); tbody.innerHTML=''; const list = $('admin-userlist'); if(list) list.innerHTML=''; arr.forEach(u=>{ const tr=document.createElement('tr'); tr.innerHTML = `<td>${u.username}</td><td>${u.email||''}</td><td>${u.balances.EUR||0}</td><td>${u.balances.BTC||0}</td><td>${u.balances.ETH||0}</td><td>${u.balances.USDT||0}</td><td>${u.banned? 'Yes':'No'}</td><td><button class="ban-btn" data-user="${u.username}">${u.banned? 'Unban':'Ban'}</button> <button class="set-btn" data-user="${u.username}">Set Balance</button> <button class="exp-btn" data-user="${u.username}">Export</button></td>`; tbody.appendChild(tr); if(list){ const li=document.createElement('div'); li.textContent = u.username; li.dataset.user = u.username; li.addEventListener('click', ()=>{ loadAdminChat(u.username); }); list.appendChild(li); } }); document.querySelectorAll('.ban-btn').forEach(b=>b.addEventListener('click', async ()=>{ const u=b.dataset.user; const ban = b.textContent.trim().toLowerCase()==='ban'; await fetch('/api/admin/ban',{ method:'POST', headers:{ 'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('token') }, body: JSON.stringify({ username:u, ban: ban }) }); fetchUsers(); })); document.querySelectorAll('.set-btn').forEach(b=>b.addEventListener('click', async ()=>{ const u=b.dataset.user; const cur=prompt('Currency (EUR,BTC,ETH,USDT):','EUR'); if(!cur) return; const v=parseFloat(prompt('Amount:','0')); if(isNaN(v)) return; await fetch('/api/admin/set-balance',{ method:'POST', headers:{ 'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('token') }, body: JSON.stringify({ username:u, currency:cur, amount: v }) }); fetchUsers(); })); document.querySelectorAll('.exp-btn').forEach(b=>b.addEventListener('click', ()=>{ const u=b.dataset.user; window.open('/api/transactions/export?username='+encodeURIComponent(u), '_blank'); })); }

async function loadAdminChat(username){ const res = await fetch('/api/admin/chat/'+encodeURIComponent(username), { headers:{ Authorization:'Bearer '+localStorage.getItem('token') } }); if(!res.ok) return; const msgs = await res.json(); const h = $('admin-chat-history'); h.innerHTML=''; (msgs||[]).forEach(m=>{ const d=document.createElement('div'); d.textContent = m.from+': '+m.text; h.appendChild(d); }); h.scrollTop = h.scrollHeight; }

if(location.pathname.endsWith('dashboard.html') || location.pathname.endsWith('admin.html')){ if(!localStorage.getItem('token')) location.href='/'; else{ if(!socket) connectSocket(); if(location.pathname.endsWith('dashboard.html')) initDashboard(); if(location.pathname.endsWith('admin.html')) initAdmin(); } }