const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DOCS_DIR = path.join(DATA_DIR, 'docs');
const TMP_DIR = path.join(DATA_DIR, 'tmp');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const BASE_URL = process.env.BASE_URL || 'https://pdf.smarbiz.sbs';

for (const dir of [DATA_DIR, DOCS_DIR, TMP_DIR]) fs.mkdirSync(dir, { recursive: true });

function loadJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function saveJson(file, value) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
  fs.renameSync(tmp, file);
}
function loadDb() { return loadJson(DB_FILE, { documents: [] }); }
function saveDb(db) { saveJson(DB_FILE, db); }

let config = loadJson(CONFIG_FILE, null);
if (!config) {
  config = { sessionSecret: crypto.randomBytes(48).toString('hex'), adminHash: null };
  saveJson(CONFIG_FILE, config);
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use('/static', express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));
app.use(session({
  name: 'pdfportal.sid',
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

const upload = multer({
  dest: TMP_DIR,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null, file.mimetype === 'application/pdf' || file.originalname.toLowerCase().endsWith('.pdf'))
});

function e(value = '') {
  return String(value).replace(/[&<>'"]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[ch]));
}
function randomId(bytes = 10) { return crypto.randomBytes(bytes).toString('hex'); }
function fmtDate(value) {
  if (!value) return '–';
  try { return new Intl.DateTimeFormat('de-DE', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Europe/Berlin' }).format(new Date(value)); }
  catch { return value; }
}
function clientIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }
function getDocByToken(token) { return loadDb().documents.find(d => d.token === token); }
function getDocById(id) { return loadDb().documents.find(d => d.id === id); }
function isExpired(doc) { return doc.expiresAt && Date.now() > new Date(doc.expiresAt).getTime(); }
function accessBlocked(doc) {
  if (!doc.active) return 'Dieser Zugriff wurde gesperrt.';
  if (isExpired(doc)) return 'Dieser Zugriff ist abgelaufen.';
  if (doc.maxOpens > 0 && doc.openCount >= doc.maxOpens) return 'Die maximale Anzahl an Öffnungen wurde erreicht.';
  return null;
}
function addLog(doc, req, event, detail = '') {
  doc.logs = doc.logs || [];
  doc.logs.unshift({ at: new Date().toISOString(), event, detail, ip: clientIp(req), userAgent: String(req.headers['user-agent'] || '').slice(0, 300) });
  doc.logs = doc.logs.slice(0, 500);
}
function persistDoc(updated) {
  const db = loadDb();
  const i = db.documents.findIndex(d => d.id === updated.id);
  if (i >= 0) db.documents[i] = updated;
  saveDb(db);
}
function adminOnly(req, res, next) {
  if (!config.adminHash) return res.redirect('/setup');
  if (!req.session.admin) return res.redirect('/admin/login');
  next();
}
function viewerKey(doc) { return `doc_${doc.id}`; }
function hasViewerAccess(req, doc) { return !!(req.session.viewerAccess && req.session.viewerAccess[viewerKey(doc)]); }
function ensureDeviceCookie(req, res) {
  const raw = String(req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('pdfdevice='));
  let id = raw ? decodeURIComponent(raw.slice('pdfdevice='.length)) : '';
  if (!/^[a-f0-9]{32}$/.test(id)) {
    id = randomId(16);
    res.cookie('pdfdevice', id, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 365 * 24 * 60 * 60 * 1000 });
  }
  return id;
}
function verifyPdfMagic(file) {
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(5);
  fs.readSync(fd, buf, 0, 5, 0);
  fs.closeSync(fd);
  return buf.toString() === '%PDF-';
}

function shell(title, body, extra = '') {
  return `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${e(title)}</title><link rel="stylesheet" href="/static/styles.css">${extra}</head><body>${body}</body></html>`;
}
function adminNav(title) {
  return `<header class="topbar"><div><a class="brand" href="/admin">PDF Protect</a><span class="muted">${e(title)}</span></div><form method="post" action="/admin/logout"><button class="linkbtn">Abmelden</button></form></header>`;
}

app.get('/', (_req, res) => res.redirect('/admin'));

app.get('/health', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get('/setup', (_req, res) => {
  if (config.adminHash) return res.redirect('/admin/login');
  res.send(shell('Einrichtung', `<main class="center"><section class="card auth"><h1>PDF Protect einrichten</h1><p class="muted">Einmalig ein Admin-Passwort festlegen.</p><form method="post"><label>Admin-Passwort<input type="password" name="password" minlength="8" required autofocus></label><button class="primary" type="submit">Einrichten</button></form></section></main>`));
});
app.post('/setup', async (req, res) => {
  if (config.adminHash) return res.redirect('/admin/login');
  const password = String(req.body.password || '');
  if (password.length < 8) return res.status(400).send(shell('Fehler', '<main class="center"><section class="card auth"><h1>Passwort zu kurz</h1><p>Mindestens 8 Zeichen.</p><a href="/setup">Zurück</a></section></main>'));
  config.adminHash = await bcrypt.hash(password, 12);
  saveJson(CONFIG_FILE, config);
  req.session.admin = true;
  res.redirect('/admin');
});

app.get('/admin/login', (_req, res) => {
  if (!config.adminHash) return res.redirect('/setup');
  res.send(shell('Admin Login', `<main class="center"><section class="card auth"><h1>Admin Login</h1><form method="post"><label>Passwort<input type="password" name="password" required autofocus></label><button class="primary" type="submit">Anmelden</button></form></section></main>`));
});
app.post('/admin/login', async (req, res) => {
  if (!config.adminHash) return res.redirect('/setup');
  if (await bcrypt.compare(String(req.body.password || ''), config.adminHash)) {
    req.session.admin = true;
    return res.redirect('/admin');
  }
  res.status(401).send(shell('Login fehlgeschlagen', '<main class="center"><section class="card auth"><h1>Falsches Passwort</h1><a href="/admin/login">Erneut versuchen</a></section></main>'));
});
app.post('/admin/logout', (req, res) => req.session.destroy(() => res.redirect('/admin/login')));

app.get('/admin', adminOnly, (_req, res) => {
  const db = loadDb();
  const rows = db.documents.map(doc => `<tr>
    <td><strong>${e(doc.title)}</strong><div class="tiny">${e(doc.buyerName || doc.buyerEmail || 'Ohne Käufername')}</div></td>
    <td><span class="badge ${doc.active && !isExpired(doc) ? 'ok' : 'off'}">${doc.active ? (isExpired(doc) ? 'Abgelaufen' : 'Aktiv') : 'Gesperrt'}</span></td>
    <td>${doc.openCount || 0}${doc.maxOpens > 0 ? ` / ${doc.maxOpens}` : ''}</td>
    <td>${(doc.devices || []).length}${doc.maxDevices > 0 ? ` / ${doc.maxDevices}` : ''}</td>
    <td>${fmtDate(doc.expiresAt)}</td>
    <td class="actions"><a href="/admin/docs/${doc.id}">Details</a></td>
  </tr>`).join('');
  res.send(shell('Dashboard', `${adminNav('Dashboard')}<main class="wrap"><div class="heading"><div><h1>Geschützte PDFs</h1><p class="muted">Einfacher Zugriffsschutz ohne direkten PDF-Download.</p></div><a class="button primary" href="/admin/new">+ Neue PDF</a></div><section class="card tablewrap"><table><thead><tr><th>Dokument</th><th>Status</th><th>Öffnungen</th><th>Geräte</th><th>Ablauf</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="6" class="empty">Noch keine PDFs angelegt.</td></tr>'}</tbody></table></section></main>`));
});

app.get('/admin/new', adminOnly, (_req, res) => {
  res.send(shell('Neue PDF', `${adminNav('Neue PDF')}<main class="wrap narrow"><section class="card"><h1>Neue geschützte PDF</h1><form method="post" enctype="multipart/form-data" action="/admin/docs" class="stack">
    <label>Titel<input name="title" required placeholder="z. B. Workbook Modul 1"></label>
    <label>PDF-Datei<input type="file" name="pdf" accept="application/pdf,.pdf" required></label>
    <div class="grid2"><label>Name des Käufers<input name="buyerName" placeholder="Max Mustermann"></label><label>E-Mail des Käufers<input type="email" name="buyerEmail" placeholder="max@example.com"></label></div>
    <label>Zugangs-Passwort<input name="accessPassword" minlength="4" required placeholder="Passwort für den Käufer"></label>
    <div class="grid3"><label>Max. Öffnungen<input type="number" name="maxOpens" min="0" value="0"><span class="hint">0 = unbegrenzt</span></label><label>Max. Geräte<input type="number" name="maxDevices" min="0" value="2"><span class="hint">0 = unbegrenzt</span></label><label>Zugriff bis<input type="datetime-local" name="expiresAt"><span class="hint">leer = unbegrenzt</span></label></div>
    <button class="primary" type="submit">PDF schützen</button>
  </form></section></main>`));
});

app.post('/admin/docs', adminOnly, upload.single('pdf'), async (req, res) => {
  if (!req.file) return res.status(400).send('PDF fehlt.');
  const tempFile = req.file.path;
  try {
    if (!verifyPdfMagic(tempFile)) throw new Error('Die Datei ist keine gültige PDF.');
    const id = randomId(8);
    const token = randomId(14);
    const dir = path.join(DOCS_DIR, id);
    fs.mkdirSync(dir, { recursive: true });
    const source = path.join(dir, 'source.pdf');
    fs.renameSync(tempFile, source);
    await execFileAsync('pdftoppm', ['-jpeg', '-jpegopt', 'quality=82', '-r', '130', source, path.join(dir, 'page')], { maxBuffer: 10 * 1024 * 1024 });
    const pages = fs.readdirSync(dir).filter(f => /^page-.*\.jpg$/i.test(f)).sort();
    if (!pages.length) throw new Error('PDF konnte nicht verarbeitet werden.');
    const accessPassword = String(req.body.accessPassword || '');
    const doc = {
      id, token,
      title: String(req.body.title || 'Dokument').trim().slice(0, 150),
      buyerName: String(req.body.buyerName || '').trim().slice(0, 150),
      buyerEmail: String(req.body.buyerEmail || '').trim().slice(0, 200),
      passwordHash: await bcrypt.hash(accessPassword, 10),
      createdAt: new Date().toISOString(),
      expiresAt: req.body.expiresAt ? new Date(req.body.expiresAt).toISOString() : null,
      maxOpens: Math.max(0, Number(req.body.maxOpens || 0) || 0),
      maxDevices: Math.max(0, Number(req.body.maxDevices || 0) || 0),
      openCount: 0,
      active: true,
      pages,
      devices: [],
      logs: []
    };
    const db = loadDb(); db.documents.unshift(doc); saveDb(db);
    res.redirect(`/admin/docs/${id}?created=1`);
  } catch (err) {
    try { if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile); } catch {}
    res.status(400).send(shell('Fehler', `${adminNav('Fehler')}<main class="wrap narrow"><section class="card"><h1>PDF konnte nicht angelegt werden</h1><p>${e(err.message)}</p><a href="/admin/new">Zurück</a></section></main>`));
  }
});

app.get('/admin/docs/:id', adminOnly, (req, res) => {
  const doc = getDocById(req.params.id);
  if (!doc) return res.status(404).send('Nicht gefunden');
  const shareUrl = `${BASE_URL}/d/${doc.token}`;
  const logs = (doc.logs || []).slice(0, 100).map(log => `<tr><td>${fmtDate(log.at)}</td><td>${e(log.event)}</td><td>${e(log.ip)}</td><td class="ua">${e(log.detail || log.userAgent)}</td></tr>`).join('');
  const deviceRows = (doc.devices || []).map(d => `<li><code>${e(d.id.slice(0, 8))}…</code> · zuerst ${fmtDate(d.firstSeen)} · zuletzt ${fmtDate(d.lastSeen)}</li>`).join('');
  res.send(shell(doc.title, `${adminNav('Dokument')}<main class="wrap"><div class="heading"><div><h1>${e(doc.title)}</h1><p class="muted">Erstellt ${fmtDate(doc.createdAt)}</p></div><a class="button" href="/admin">← Übersicht</a></div>
  <div class="grid2 maincols"><section class="card"><h2>Zugangslink</h2><div class="copyrow"><input id="shareUrl" readonly value="${e(shareUrl)}"><button type="button" onclick="navigator.clipboard.writeText(document.getElementById('shareUrl').value);this.textContent='Kopiert'">Kopieren</button></div><p class="hint">PDF selbst ist nicht öffentlich verlinkt. Der Käufer sieht nur die gerenderten Seiten.</p>
  <dl><dt>Käufer</dt><dd>${e(doc.buyerName || '–')}</dd><dt>E-Mail</dt><dd>${e(doc.buyerEmail || '–')}</dd><dt>Öffnungen</dt><dd>${doc.openCount || 0}${doc.maxOpens > 0 ? ` / ${doc.maxOpens}` : ' / ∞'}</dd><dt>Geräte</dt><dd>${(doc.devices || []).length}${doc.maxDevices > 0 ? ` / ${doc.maxDevices}` : ' / ∞'}</dd><dt>Ablauf</dt><dd>${fmtDate(doc.expiresAt)}</dd><dt>Seiten</dt><dd>${doc.pages.length}</dd></dl>
  <form method="post" action="/admin/docs/${doc.id}/toggle"><button class="${doc.active ? 'danger' : 'primary'}" type="submit">${doc.active ? 'Zugriff sperren' : 'Zugriff wieder freigeben'}</button></form></section>
  <section class="card"><h2>Registrierte Geräte</h2><ul class="plain">${deviceRows || '<li class="muted">Noch kein Gerät.</li>'}</ul></section></div>
  <section class="card"><h2>Aktivitätsprotokoll</h2><div class="tablewrap"><table><thead><tr><th>Zeit</th><th>Ereignis</th><th>IP</th><th>Details</th></tr></thead><tbody>${logs || '<tr><td colspan="4" class="empty">Noch keine Aktivität.</td></tr>'}</tbody></table></div></section></main>`));
});

app.post('/admin/docs/:id/toggle', adminOnly, (req, res) => {
  const doc = getDocById(req.params.id);
  if (!doc) return res.status(404).send('Nicht gefunden');
  doc.active = !doc.active;
  addLog(doc, req, doc.active ? 'ADMIN_FREIGEGEBEN' : 'ADMIN_GESPERRT');
  persistDoc(doc);
  res.redirect(`/admin/docs/${doc.id}`);
});

app.get('/d/:token', (req, res) => {
  const doc = getDocByToken(req.params.token);
  if (!doc) return res.status(404).send(shell('Nicht gefunden', '<main class="center"><section class="card auth"><h1>Link ungültig</h1><p>Dieses Dokument wurde nicht gefunden.</p></section></main>'));
  ensureDeviceCookie(req, res);
  if (hasViewerAccess(req, doc)) return res.redirect(`/d/${doc.token}/view`);
  const blocked = accessBlocked(doc);
  if (blocked) return res.status(403).send(shell('Zugriff nicht möglich', `<main class="center"><section class="card auth"><h1>Zugriff nicht möglich</h1><p>${e(blocked)}</p></section></main>`));
  res.setHeader('Cache-Control', 'no-store');
  res.send(shell(doc.title, `<main class="center"><section class="card auth"><div class="lock">🔒</div><h1>${e(doc.title)}</h1>${doc.buyerName ? `<p class="muted">Für ${e(doc.buyerName)}</p>` : ''}<form method="post"><label>Passwort<input type="password" name="password" required autofocus autocomplete="current-password"></label><button class="primary" type="submit">Dokument öffnen</button></form><p class="tiny centertext">Persönlich geschützter Zugriff. Aktivitäten können protokolliert werden.</p></section></main>`));
});

app.post('/d/:token', async (req, res) => {
  const doc = getDocByToken(req.params.token);
  if (!doc) return res.status(404).send('Nicht gefunden');
  const deviceId = ensureDeviceCookie(req, res);
  const blocked = accessBlocked(doc);
  if (blocked) return res.status(403).send(shell('Zugriff nicht möglich', `<main class="center"><section class="card auth"><h1>Zugriff nicht möglich</h1><p>${e(blocked)}</p></section></main>`));
  if (!(await bcrypt.compare(String(req.body.password || ''), doc.passwordHash))) {
    addLog(doc, req, 'PASSWORT_FEHLER'); persistDoc(doc);
    return res.status(401).send(shell('Falsches Passwort', `<main class="center"><section class="card auth"><h1>Falsches Passwort</h1><a href="/d/${doc.token}">Erneut versuchen</a></section></main>`));
  }
  doc.devices = doc.devices || [];
  let device = doc.devices.find(d => d.id === deviceId);
  if (!device) {
    if (doc.maxDevices > 0 && doc.devices.length >= doc.maxDevices) {
      addLog(doc, req, 'GERAET_ABGELEHNT', 'Gerätelimit erreicht'); persistDoc(doc);
      return res.status(403).send(shell('Gerätelimit', '<main class="center"><section class="card auth"><h1>Gerätelimit erreicht</h1><p>Dieses Dokument ist bereits auf der maximal erlaubten Anzahl an Geräten aktiviert.</p></section></main>'));
    }
    device = { id: deviceId, firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString() };
    doc.devices.push(device);
  } else device.lastSeen = new Date().toISOString();
  doc.openCount = (doc.openCount || 0) + 1;
  addLog(doc, req, 'GEÖFFNET', `Gerät ${deviceId.slice(0, 8)}…`);
  persistDoc(doc);
  req.session.viewerAccess = req.session.viewerAccess || {};
  req.session.viewerAccess[viewerKey(doc)] = true;
  res.redirect(`/d/${doc.token}/view`);
});

app.get('/d/:token/view', (req, res) => {
  const doc = getDocByToken(req.params.token);
  if (!doc) return res.status(404).send('Nicht gefunden');
  if (!hasViewerAccess(req, doc)) return res.redirect(`/d/${doc.token}`);
  const blocked = !doc.active ? 'Dieser Zugriff wurde gesperrt.' : (isExpired(doc) ? 'Dieser Zugriff ist abgelaufen.' : null);
  if (blocked) return res.status(403).send(shell('Zugriff nicht möglich', `<main class="center"><section class="card auth"><h1>Zugriff nicht möglich</h1><p>${e(blocked)}</p></section></main>`));
  const watermark = [doc.buyerName, doc.buyerEmail].filter(Boolean).join(' · ') || `Zugriff ${doc.id}`;
  const watermarks = Array.from({ length: 28 }, () => `<span>${e(watermark)}</span>`).join('');
  const pages = doc.pages.map((p, i) => `<figure class="pdfpage"><img src="/d/${doc.token}/page/${i + 1}" alt="Seite ${i + 1}" draggable="false"><figcaption>${i + 1} / ${doc.pages.length}</figcaption></figure>`).join('');
  res.setHeader('Cache-Control', 'no-store');
  res.send(shell(doc.title, `<header class="viewerbar"><strong>${e(doc.title)}</strong><span>${doc.pages.length} Seiten</span></header><main class="viewer" oncontextmenu="return false">${pages}<div class="watermark-grid" aria-hidden="true">${watermarks}</div></main><script>document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&['s','p'].includes(e.key.toLowerCase()))e.preventDefault()});</script>`));
});

app.get('/d/:token/page/:page', (req, res) => {
  const doc = getDocByToken(req.params.token);
  if (!doc || !hasViewerAccess(req, doc) || !doc.active || isExpired(doc)) return res.status(403).end();
  const n = Number(req.params.page);
  if (!Number.isInteger(n) || n < 1 || n > doc.pages.length) return res.status(404).end();
  const file = path.join(DOCS_DIR, doc.id, doc.pages[n - 1]);
  res.setHeader('Cache-Control', 'private, no-store, max-age=0');
  res.setHeader('Content-Disposition', 'inline');
  res.sendFile(file);
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).send(shell('Fehler', '<main class="center"><section class="card auth"><h1>Etwas ist schiefgelaufen</h1><p>Bitte erneut versuchen.</p></section></main>'));
});

app.listen(PORT, '127.0.0.1', () => console.log(`PDF Protect listening on http://127.0.0.1:${PORT}`));
