/*
 * Murmur – a mini social media app in ONE file.
 *
 * Run in the VS Code terminal:
 *   npm init -y
 *   npm install express better-sqlite3
 *   node murmur.js        ->  http://localhost:3000
 *
 * Features: sign up / log in, user profiles with bio, posts, comments,
 * likes, follow / unfollow, "Everyone" and "Following" feeds.
 * Data lives in social.db (SQLite) next to this file.
 * Demo accounts on first run: ada / grace, password "password1".
 */
const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());

// ======================= DATABASE =======================
const db = new Database(path.join(__dirname, 'social.db'));
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE, salt TEXT, hash TEXT, bio TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id));
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS likes(user_id INTEGER NOT NULL, post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE, PRIMARY KEY(user_id, post_id));
CREATE TABLE IF NOT EXISTS follows(follower_id INTEGER NOT NULL, followee_id INTEGER NOT NULL, PRIMARY KEY(follower_id, followee_id));
`);

const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
function createUser(username, pw, bio = '') {
  const salt = crypto.randomBytes(8).toString('hex');
  return db.prepare('INSERT INTO users(username,salt,hash,bio) VALUES(?,?,?,?)').run(username, salt, hashPw(pw, salt), bio).lastInsertRowid;
}
function newSession(userId) {
  const t = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?)').run(t, userId);
  return t;
}
if (!db.prepare('SELECT 1 FROM users').get()) { // seed demo data
  const a = createUser('ada', 'password1', 'Wrote the first program.');
  const g = createUser('grace', 'password1', 'Compilers, debugging, nanoseconds.');
  const ins = db.prepare('INSERT INTO posts(user_id,body) VALUES(?,?)');
  ins.run(a, 'Hello Murmur! First post.'); ins.run(g, 'Found the bug. It was an actual moth.');
}

const POSTS = `SELECT p.id, p.body, p.created_at, u.username,
  (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes,
  (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND user_id = @me) AS liked,
  (SELECT COUNT(*) FROM comments WHERE post_id = p.id) AS comments
  FROM posts p JOIN users u ON u.id = p.user_id`;
const clean = (s, max) => String(s || '').trim().slice(0, max);

// ======================= AUTH =======================
const auth = (req, res, next) => {
  const t = (req.get('Authorization') || '').replace('Bearer ', '');
  const u = t && db.prepare('SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?').get(t);
  if (!u) return res.status(401).json({ error: 'Please log in.' });
  req.user = u; req.token = t; next();
};

app.post('/api/register', (req, res) => {
  const username = clean(req.body.username, 20), pw = String(req.body.password || '');
  if (!/^[a-z0-9_]{3,20}$/i.test(username)) return res.status(400).json({ error: 'Username must be 3 to 20 letters, numbers or underscores.' });
  if (pw.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) return res.status(409).json({ error: 'That username is taken.' });
  const id = createUser(username, pw);
  res.status(201).json({ token: newSession(id), user: { username, bio: '' } });
});

app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(clean(req.body.username, 20));
  const ok = u && crypto.timingSafeEqual(Buffer.from(u.hash, 'hex'), Buffer.from(hashPw(String(req.body.password || ''), u.salt), 'hex'));
  if (!ok) return res.status(401).json({ error: 'Wrong username or password.' });
  res.json({ token: newSession(u.id), user: { username: u.username, bio: u.bio } });
});

app.post('/api/logout', auth, (req, res) => { db.prepare('DELETE FROM sessions WHERE token = ?').run(req.token); res.json({}); });

app.get('/api/me', auth, (req, res) => res.json(db.prepare('SELECT username, bio FROM users WHERE id = ?').get(req.user.id)));
app.put('/api/me', auth, (req, res) => {
  db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(clean(req.body.bio, 120), req.user.id);
  res.json(db.prepare('SELECT username, bio FROM users WHERE id = ?').get(req.user.id));
});

// ======================= POSTS, LIKES, COMMENTS =======================
app.get('/api/feed', auth, (req, res) => {
  const f = req.query.scope === 'following' ? 1 : 0;
  res.json(db.prepare(`${POSTS} WHERE (@f = 0 OR p.user_id = @me OR p.user_id IN (SELECT followee_id FROM follows WHERE follower_id = @me))
    ORDER BY p.id DESC LIMIT 50`).all({ f, me: req.user.id }));
});

app.post('/api/posts', auth, (req, res) => {
  const body = clean(req.body.body, 280);
  if (!body) return res.status(400).json({ error: 'Write something first.' });
  const id = db.prepare('INSERT INTO posts(user_id, body) VALUES(?,?)').run(req.user.id, body).lastInsertRowid;
  res.status(201).json(db.prepare(`${POSTS} WHERE p.id = @id`).get({ me: req.user.id, id }));
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const r = db.prepare('DELETE FROM posts WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  r.changes ? res.json({}) : res.status(403).json({ error: 'You can only delete your own posts.' });
});

const postExists = (req, res, next) =>
  db.prepare('SELECT 1 FROM posts WHERE id = ?').get(req.params.id) ? next() : res.status(404).json({ error: 'Post not found.' });

app.post('/api/posts/:id/like', auth, postExists, (req, res) => {
  const args = [req.user.id, req.params.id];
  const had = db.prepare('SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?').get(...args);
  db.prepare(had ? 'DELETE FROM likes WHERE user_id = ? AND post_id = ?' : 'INSERT INTO likes VALUES(?,?)').run(...args);
  res.json({ liked: !had, likes: db.prepare('SELECT COUNT(*) c FROM likes WHERE post_id = ?').get(req.params.id).c });
});

app.get('/api/posts/:id/comments', auth, postExists, (req, res) =>
  res.json(db.prepare(`SELECT c.id, c.body, c.created_at, u.username FROM comments c JOIN users u ON u.id = c.user_id
    WHERE c.post_id = ? ORDER BY c.id`).all(req.params.id)));

app.post('/api/posts/:id/comments', auth, postExists, (req, res) => {
  const body = clean(req.body.body, 200);
  if (!body) return res.status(400).json({ error: 'Write something first.' });
  const id = db.prepare('INSERT INTO comments(post_id, user_id, body) VALUES(?,?,?)').run(req.params.id, req.user.id, body).lastInsertRowid;
  res.status(201).json({ id, body, username: req.user.username });
});

// ======================= PROFILES + FOLLOWS =======================
app.get('/api/suggestions', auth, (req, res) =>
  res.json(db.prepare(`SELECT username, bio FROM users WHERE id != ? AND id NOT IN
    (SELECT followee_id FROM follows WHERE follower_id = ?) ORDER BY id DESC LIMIT 5`).all(req.user.id, req.user.id)));

app.get('/api/users/:name', auth, (req, res) => {
  const u = db.prepare('SELECT id, username, bio FROM users WHERE username = ?').get(req.params.name);
  if (!u) return res.status(404).json({ error: 'User not found.' });
  const n = sql => db.prepare(sql).get(u.id).c;
  res.json({
    username: u.username, bio: u.bio, isMe: u.id === req.user.id,
    followers: n('SELECT COUNT(*) c FROM follows WHERE followee_id = ?'),
    following: n('SELECT COUNT(*) c FROM follows WHERE follower_id = ?'),
    postCount: n('SELECT COUNT(*) c FROM posts WHERE user_id = ?'),
    isFollowing: !!db.prepare('SELECT 1 FROM follows WHERE follower_id = ? AND followee_id = ?').get(req.user.id, u.id),
    posts: db.prepare(`${POSTS} WHERE p.user_id = @uid ORDER BY p.id DESC LIMIT 50`).all({ me: req.user.id, uid: u.id })
  });
});

app.post('/api/users/:name/follow', auth, (req, res) => {
  const u = db.prepare('SELECT id FROM users WHERE username = ?').get(req.params.name);
  if (!u) return res.status(404).json({ error: 'User not found.' });
  if (u.id === req.user.id) return res.status(400).json({ error: 'You cannot follow yourself.' });
  const args = [req.user.id, u.id];
  const had = db.prepare('SELECT 1 FROM follows WHERE follower_id = ? AND followee_id = ?').get(...args);
  db.prepare(had ? 'DELETE FROM follows WHERE follower_id = ? AND followee_id = ?' : 'INSERT INTO follows VALUES(?,?)').run(...args);
  res.json({ following: !had });
});

app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Server error.' }); });

// ======================= FRONTEND: CSS =======================
const CSS = String.raw`
:root{--bg:#eef0f6;--ink:#161b2e;--muted:#667090;--line:#dde1ee;--card:#fff;--acc:#4b3fe0;--onacc:#fff;--like:#e0245e;--err:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#0f1220;--ink:#e9ebf7;--muted:#99a1c6;--line:#2a3050;--card:#181c30;--acc:#8f86ff;--onacc:#0f1220;--like:#ff6b97;--err:#ff9a90}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:inherit;text-decoration:none}a:hover strong{text-decoration:underline}
:focus-visible{outline:3px solid var(--acc);outline-offset:2px}
h1{font-size:1.5rem;margin:0 0 .4rem}h2{font-size:1.05rem;margin:0 0 .6rem}
.top{display:flex;justify-content:space-between;align-items:center;padding:.8rem clamp(1rem,4vw,2.5rem);background:var(--card);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.brand{font:700 1.6rem Georgia,serif;letter-spacing:-.02em}
#nav{display:flex;gap:1.2rem;align-items:center}#nav a{font-weight:600}
main{max-width:920px;margin:0 auto;padding:1.5rem clamp(1rem,4vw,2rem) 4rem}
.cols{display:grid;grid-template-columns:1fr 260px;gap:1.5rem;align-items:start}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem;margin-bottom:.9rem}
input,textarea{font:inherit;width:100%;padding:.6rem .75rem;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}
textarea{resize:vertical;min-height:70px}
label{display:block;margin:.8rem 0 .25rem;font-weight:600;font-size:.92rem}
.btn{background:var(--acc);color:var(--onacc);border:0;border-radius:999px;padding:.5rem 1.1rem;font:600 .95rem inherit;font-family:inherit;cursor:pointer}
.btn.ghost{background:none;color:var(--acc);border:1.5px solid var(--acc)}.btn.wide{width:100%;margin-top:1rem;border-radius:8px}
.btn:disabled{opacity:.5}
.row{display:flex;justify-content:space-between;align-items:center;margin-top:.5rem}
.meta{color:var(--muted);font-size:.9rem}.error{color:var(--err);margin:.6rem 0 0}
.link{background:none;border:0;color:var(--muted);font:inherit;cursor:pointer;padding:0}
.tabs{display:flex;gap:.4rem;margin-bottom:.9rem}
.tabs button{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:999px;padding:.35rem .9rem;font:inherit;cursor:pointer}
.tabs button.on{background:var(--acc);color:var(--onacc);border-color:var(--acc)}
.post{display:flex;gap:.8rem}.pb{flex:1;min-width:0}.pb p{margin:.2rem 0 .4rem;overflow-wrap:anywhere;white-space:pre-wrap}
.av{flex:none;width:42px;height:42px;border-radius:50%;background:var(--acc);color:var(--onacc);display:grid;place-items:center;font-weight:700}
.av.big{width:72px;height:72px;font-size:1.8rem}
.acts{display:flex;gap:.4rem}
.act{background:none;border:0;color:var(--muted);font:inherit;cursor:pointer;padding:.2rem .5rem;border-radius:6px}
.act:hover{background:var(--bg)}.act.liked{color:var(--like);font-weight:700}
.cmts{margin-top:.5rem;padding-top:.6rem;border-top:1px solid var(--line)}.cmt{padding:.25rem 0}
.cform{display:flex;gap:.5rem;margin-top:.5rem}
.head{display:flex;gap:1rem;align-items:center}.head>div:last-child{flex:1}.head p{margin:.2rem 0}
.stats{display:flex;gap:1.2rem;margin:.4rem 0 .7rem}
.who{display:flex;justify-content:space-between;align-items:center;gap:.5rem;padding:.4rem 0}
.who .meta{display:block;font-size:.82rem}
.auth{max-width:380px;margin:2rem auto}
.toast{position:fixed;bottom:1.2rem;left:50%;transform:translateX(-50%);background:var(--ink);color:var(--bg);padding:.6rem 1.1rem;border-radius:8px;z-index:9}
@media(max-width:760px){.cols{grid-template-columns:1fr}}
`;

// ======================= FRONTEND: JS (runs in the browser) =======================
// CLIENT_START
function client() {
  const $ = s => document.querySelector(s), app = $('#app'), nav = $('#nav');
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const mem = {};
  const store = {
    get(k) { try { return localStorage.getItem(k) || mem[k] || null; } catch (e) { return mem[k] || null; } },
    set(k, v) { mem[k] = v; try { localStorage.setItem(k, v); } catch (e) {} },
    del(k) { delete mem[k]; try { localStorage.removeItem(k); } catch (e) {} }
  };
  let token = store.get('token'), me = null, view = ['home'], scope = 'all', mode = 'login';

  const ago = s => {
    const m = Math.max(0, (Date.now() - new Date(s.replace(' ', 'T') + 'Z')) / 60000);
    return m < 1 ? 'just now' : m < 60 ? Math.floor(m) + 'm ago' : m < 1440 ? Math.floor(m / 60) + 'h ago' : Math.floor(m / 1440) + 'd ago';
  };
  let timer;
  const toast = msg => {
    let t = $('.toast'); if (t) t.remove();
    t = document.createElement('div'); t.className = 'toast'; t.setAttribute('role', 'status'); t.textContent = msg; document.body.append(t);
    clearTimeout(timer); timer = setTimeout(() => t.remove(), 2500);
  };
  const api = async (url, method = 'GET', body) => {
    const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
    const d = await r.json();
    if (r.status === 401 && token) logout();
    if (!r.ok) throw new Error(d.error || 'Something went wrong.');
    return d;
  };
  const logout = () => { store.del('token'); token = null; me = null; view = ['home']; render(); };

  const cols = (main, side) => `<div class="cols"><section>${main}</section><aside>${side}</aside></div>`;
  const av = (name, big) => `<div class="av ${big ? 'big' : ''}" aria-hidden="true">${esc(name[0].toUpperCase())}</div>`;

  const postHtml = p => `
    <article class="panel post">${av(p.username)}
      <div class="pb">
        <div><a href="#" data-go="profile:${esc(p.username)}"><strong>@${esc(p.username)}</strong></a> <span class="meta">${ago(p.created_at)}</span></div>
        <p>${esc(p.body)}</p>
        <div class="acts">
          <button class="act ${p.liked ? 'liked' : ''}" data-like="${p.id}" aria-pressed="${!!p.liked}" aria-label="Like">♥ <span>${p.likes}</span></button>
          <button class="act" data-cmt="${p.id}" aria-label="Comments">💬 <span>${p.comments}</span></button>
          ${p.username === me.username ? `<button class="act" data-del="${p.id}">Delete</button>` : ''}
        </div>
        <div class="cmts" id="c${p.id}" hidden></div>
      </div>
    </article>`;

  async function suggestions() {
    const list = await api('/api/suggestions');
    return `<div class="panel"><h2>Who to follow</h2>${list.length ? list.map(u => `
      <div class="who"><div><a href="#" data-go="profile:${esc(u.username)}"><strong>@${esc(u.username)}</strong></a><span class="meta">${esc(u.bio || 'New here')}</span></div>
      <button class="btn ghost" data-follow="${esc(u.username)}">Follow</button></div>`).join('') : '<p class="meta">You follow everyone here.</p>'}</div>`;
  }

  async function home() {
    const [posts, side] = await Promise.all([api('/api/feed?scope=' + scope), suggestions()]);
    app.innerHTML = cols(`
      <form class="panel" data-post="1"><textarea maxlength="280" placeholder="What’s on your mind?" aria-label="New post"></textarea>
        <div class="row"><span class="meta">Up to 280 characters</span><button class="btn">Post</button></div><p class="error"></p></form>
      <div class="tabs"><button data-scope="all" class="${scope === 'all' ? 'on' : ''}">Everyone</button><button data-scope="following" class="${scope === 'following' ? 'on' : ''}">Following</button></div>
      ${posts.length ? posts.map(postHtml).join('') : '<p class="meta">Nothing here yet. Follow people or write the first post.</p>'}`, side);
  }

  async function profile(name) {
    const [u, side] = await Promise.all([api('/api/users/' + encodeURIComponent(name)), suggestions()]);
    app.innerHTML = cols(`
      <div class="panel head">${av(u.username, true)}<div><h1>@${esc(u.username)}</h1>
        <p>${u.bio ? esc(u.bio) : '<span class="meta">No bio yet.</span>'}</p>
        <div class="stats"><span><strong>${u.postCount}</strong> posts</span><span><strong>${u.followers}</strong> followers</span><span><strong>${u.following}</strong> following</span></div>
        ${u.isMe ? `<form class="cform" data-bioform="1"><input maxlength="120" value="${esc(u.bio)}" placeholder="Write a short bio" aria-label="Bio"><button class="btn">Save</button></form>`
          : `<button class="btn ${u.isFollowing ? 'ghost' : ''}" data-follow="${esc(u.username)}">${u.isFollowing ? 'Unfollow' : 'Follow'}</button>`}
      </div></div>
      ${u.posts.length ? u.posts.map(postHtml).join('') : '<p class="meta">No posts yet.</p>'}`, side);
  }

  function authView() {
    nav.innerHTML = '';
    const login = mode === 'login';
    app.innerHTML = `<div class="panel auth"><h1>${login ? 'Welcome back' : 'Join Murmur'}</h1>
      <form data-auth="${mode}"><label for="u">Username</label><input id="u" autocomplete="username" required>
        <label for="p">Password</label><input id="p" type="password" autocomplete="${login ? 'current-password' : 'new-password'}" required>
        <p class="error" role="alert"></p><button class="btn wide">${login ? 'Log in' : 'Create account'}</button></form>
      <p class="meta">${login ? 'New here?' : 'Already have an account?'} <a href="#" data-mode="${login ? 'register' : 'login'}"><strong>${login ? 'Create an account' : 'Log in'}</strong></a></p></div>`;
  }

  async function render() {
    if (!token) return authView();
    try {
      if (!me) me = await api('/api/me');
      nav.innerHTML = `<a href="#" data-go="home">Home</a><a href="#" data-go="profile:${esc(me.username)}">Profile</a><button class="link" data-logout="1">Log out</button>`;
      await ({ home, profile })[view[0]](view[1]);
    } catch (e) { if (token) toast(e.message); }
  }

  async function showComments(id) {
    const list = await api(`/api/posts/${id}/comments`), box = $('#c' + id);
    box.innerHTML = list.map(c => `<div class="cmt"><a href="#" data-go="profile:${esc(c.username)}"><strong>@${esc(c.username)}</strong></a> ${esc(c.body)}</div>`).join('') +
      `<form class="cform" data-cform="${id}"><input maxlength="200" placeholder="Write a comment" aria-label="Comment"><button class="btn">Reply</button></form>`;
    box.hidden = false;
    $(`[data-cmt="${id}"] span`).textContent = list.length;
  }

  document.addEventListener('click', async e => {
    const el = e.target.closest('[data-go],[data-like],[data-cmt],[data-del],[data-follow],[data-scope],[data-logout],[data-mode]');
    if (!el) return;
    e.preventDefault();
    const d = el.dataset;
    try {
      if (d.go) { view = d.go.split(':'); window.scrollTo(0, 0); return render(); }
      if (d.mode) { mode = d.mode; return authView(); }
      if (d.logout) { await api('/api/logout', 'POST').catch(() => {}); return logout(); }
      if (d.scope) { scope = d.scope; return render(); }
      if (d.follow) { await api(`/api/users/${encodeURIComponent(d.follow)}/follow`, 'POST'); return render(); }
      if (d.del) { await api('/api/posts/' + d.del, 'DELETE'); return render(); }
      if (d.like) {
        const r = await api(`/api/posts/${d.like}/like`, 'POST');
        el.classList.toggle('liked', r.liked); el.setAttribute('aria-pressed', r.liked); el.querySelector('span').textContent = r.likes; return;
      }
      if (d.cmt) { const box = $('#c' + d.cmt); return box.hidden ? showComments(d.cmt) : (box.hidden = true); }
    } catch (err) { toast(err.message); }
  });

  document.addEventListener('submit', async e => {
    e.preventDefault();
    const f = e.target, d = f.dataset, val = sel => f.querySelector(sel).value;
    try {
      if (d.auth) {
        const r = await api('/api/' + d.auth, 'POST', { username: val('#u'), password: val('#p') });
        token = r.token; store.set('token', token); me = r.user; view = ['home']; return render();
      }
      if (d.post) { await api('/api/posts', 'POST', { body: val('textarea') }); return render(); }
      if (d.cform) { await api(`/api/posts/${d.cform}/comments`, 'POST', { body: val('input') }); return showComments(d.cform); }
      if (d.bioform) { me = await api('/api/me', 'PUT', { bio: val('input') }); toast('Bio saved'); return render(); }
    } catch (err) { const el = f.querySelector('.error'); el ? el.textContent = err.message : toast(err.message); }
  });

  render();
}
// CLIENT_END

// ======================= PAGE + START =======================
const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Murmur</title>
<style>${CSS}</style></head><body>
<header class="top"><a class="brand" href="/">Murmur</a><nav id="nav"></nav></header>
<main id="app"></main>
<script>(${client})()</script></body></html>`;

app.get('/', (req, res) => res.type('html').send(PAGE));
app.listen(PORT, () => console.log(`Murmur running at http://localhost:${PORT}`));
