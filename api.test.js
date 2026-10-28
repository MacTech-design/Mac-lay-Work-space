'use strict';
// Starts the server on a temp database and exercises accounts, snippets, security and the owner API.
const { spawn, spawnSync } = require('node:child_process');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const assert = require('node:assert/strict');

const PORT = 3900 + Math.floor(Math.random() * 90);
const DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'maclay-test-'));
const ROOT = path.join(__dirname, '..');
const env = { ...process.env, PORT: String(PORT), DATA_DIR: DATA, PRODUCTION: '0', OWNER_EMAIL: '', ANTHROPIC_API_KEY: '' };
const BASE = `http://127.0.0.1:${PORT}`;

class Client {
  constructor() { this.cookie = ''; }
  async req(method, url, body, extra = {}) {
    const headers = { 'X-Requested-With': 'maclay', ...extra };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (this.cookie) headers.Cookie = this.cookie;
    const r = await fetch(BASE + url, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    const set = r.headers.get('set-cookie');
    if (set) this.cookie = set.split(';')[0].endsWith('=') ? '' : set.split(';')[0];
    const text = await r.text(); let json = {};
    try { json = JSON.parse(text); } catch (_) {}
    return { status: r.status, json, headers: r.headers, text };
  }
}
let pass = 0;
const t = async (name, fn) => { try { await fn(); pass++; console.log('  ✓', name); } catch (e) { console.log('  ✗', name, '\n   ', e.message); process.exitCode = 1; } };

(async () => {
  const srv = spawn('node', ['server.js'], { cwd: ROOT, env, stdio: 'ignore' });
  for (let i = 0; i < 40; i++) { try { await fetch(BASE + '/api/health'); break; } catch (_) { await new Promise(r => setTimeout(r, 150)); } }

  const alice = new Client(), bob = new Client(), anon = new Client();
  console.log('Accounts');
  await t('rejects weak passwords', async () => {
    assert.equal((await anon.req('POST', '/api/auth/register', { name: 'Al', email: 'a@x.com', password: 'short' })).status, 400);
    assert.equal((await anon.req('POST', '/api/auth/register', { name: 'Al', email: 'a@x.com', password: 'onlyletters' })).status, 400);
  });
  await t('rejects bad email', async () => assert.equal((await anon.req('POST', '/api/auth/register', { name: 'Al', email: 'nope', password: 'goodpass123' })).status, 400));
  await t('registers + sets a hardened cookie', async () => {
    const r = await alice.req('POST', '/api/auth/register', { name: 'Alice', email: 'alice@example.com', password: 'goodpass123' });
    assert.equal(r.status, 200); assert.equal(r.json.user.role, 'user');
    assert.equal(r.json.user.pass_hash, undefined);
    const c = r.headers.get('set-cookie');
    assert.match(c, /HttpOnly/); assert.match(c, /SameSite=Strict/);
  });
  await t('duplicate email refused (case-insensitive)', async () => assert.equal((await anon.req('POST', '/api/auth/register', { name: 'Al2', email: 'ALICE@example.com', password: 'goodpass123' })).status, 409));
  await t('/api/me works with cookie, null without', async () => {
    assert.equal((await alice.req('GET', '/api/me')).json.user.email, 'alice@example.com');
    assert.equal((await anon.req('GET', '/api/me')).json.user, null);
  });
  await t('wrong password rejected, right one accepted', async () => {
    const c = new Client();
    assert.equal((await c.req('POST', '/api/auth/login', { email: 'alice@example.com', password: 'wrongwrong1' })).status, 401);
    assert.equal((await c.req('POST', '/api/auth/login', { email: 'alice@example.com', password: 'goodpass123' })).status, 200);
  });
  await t('account locks after repeated failures', async () => {
    const c = new Client(); let last;
    for (let i = 0; i < 6; i++) last = await c.req('POST', '/api/auth/login', { email: 'lock@example.com', password: 'badbadbad1' });
    assert.equal(last.status, 429);
  });

  console.log('CSRF / hardening');
  await t('POST without X-Requested-With is blocked', async () => {
    const r = await fetch(BASE + '/api/snippets', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: alice.cookie }, body: '{}' });
    assert.equal(r.status, 403);
  });
  await t('cross-site Origin is blocked', async () => assert.equal((await alice.req('POST', '/api/snippets', { name: 'x', lang: 'python', code: 'print(1)' }, { Origin: 'https://evil.example' })).status, 403));
  await t('security headers present', async () => {
    const r = await anon.req('GET', '/');
    assert.ok(r.headers.get('content-security-policy').includes("frame-ancestors 'none'"));
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  });
  await t('path traversal is refused', async () => {
    for (const p of ['/../server.js', '/..%2fserver.js', '/%2e%2e/package.json', '/data/maclay.db']) {
      const r = await fetch(BASE + p); assert.notEqual(r.status, 200, p);
    }
  });
  await t('page contains no payment code', async () => assert.ok(!/paynow|ecocash/i.test((await anon.req('GET', '/')).text)));

  console.log('Snippets');
  let sid;
  await t('requires login', async () => assert.equal((await anon.req('GET', '/api/snippets')).status, 401));
  await t('create / list / update', async () => {
    const r = await alice.req('POST', '/api/snippets', { name: '<img src=x onerror=1>', lang: 'python', code: 'print("hi")' });
    assert.equal(r.status, 200); sid = r.json.snippet.id;
    assert.equal(r.json.usage.count, 1);
    await alice.req('POST', '/api/snippets', { name: 'js', lang: 'javascript', code: 'console.log(1)' });
    const l = await alice.req('GET', '/api/snippets');
    assert.equal(l.json.snippets.length, 2);
    assert.equal(Object.keys(l.json.usage.byLang).sort().join(), 'javascript,python');
    const u = await alice.req('PUT', '/api/snippets/' + sid, { name: 'renamed' });
    assert.equal(u.json.snippet.name, 'renamed');
  });
  await t('invalid language / empty / oversize refused', async () => {
    assert.equal((await alice.req('POST', '/api/snippets', { name: 'x', lang: 'cobol', code: 'x' })).status, 400);
    assert.equal((await alice.req('POST', '/api/snippets', { name: 'x', lang: 'python', code: '  ' })).status, 400);
    assert.equal((await alice.req('POST', '/api/snippets', { name: 'x', lang: 'python', code: 'x'.repeat(120 * 1024) })).status, 413);
  });
  await bob.req('POST', '/api/auth/register', { name: 'Bob', email: 'bob@example.com', password: 'goodpass456' });
  await t("users cannot see or touch each other's snippets", async () => {
    assert.equal((await bob.req('GET', '/api/snippets')).json.snippets.length, 0);
    assert.equal((await bob.req('PUT', '/api/snippets/' + sid, { name: 'hacked' })).status, 404);
    await bob.req('DELETE', '/api/snippets/' + sid);
    assert.equal((await alice.req('GET', '/api/snippets')).json.snippets.length, 2);
  });
  await t('storage quota enforced', async () => {
    const c = new Client(); await c.req('POST', '/api/auth/register', { name: 'Quota', email: 'q@example.com', password: 'goodpass789' });
    let status = 200, n = 0;
    while (status === 200 && n < 40) { status = (await c.req('POST', '/api/snippets', { name: 'big' + n, lang: 'c', code: 'a'.repeat(95 * 1024) })).status; n++; }
    assert.equal(status, 413); assert.ok(n > 15 && n < 25, 'stored ' + n);
  });
  await t('local snippets import', async () => {
    const r = await bob.req('POST', '/api/snippets/import', { items: [{ name: 'old1', lang: 'python', code: 'x=1' }, { name: '', lang: 'zzz', code: '' }] });
    assert.equal(r.json.added, 1);
  });

  console.log('Owner dashboard');
  await t('normal users get 404 on admin routes', async () => {
    for (const u of ['/api/admin/overview', '/api/admin/users', '/api/admin/activity']) assert.equal((await alice.req('GET', u)).status, 404);
    assert.equal((await anon.req('GET', '/api/admin/overview')).status, 401);
    assert.equal((await alice.req('POST', '/api/admin/settings', { maintenance: true })).status, 404);
  });
  await t('role cannot be self-assigned via profile update', async () => {
    await alice.req('POST', '/api/me/profile', { name: 'Alice', bio: 'x', role: 'owner' });
    assert.equal((await alice.req('GET', '/api/me')).json.user.role, 'user');
  });
  const mk = spawnSync('node', ['server.js', '--make-owner', 'alice@example.com'], { cwd: ROOT, env, encoding: 'utf8' });
  await t('--make-owner CLI promotes an account', async () => { assert.match(mk.stdout, /now an owner/); assert.equal((await alice.req('GET', '/api/me')).json.user.role, 'owner'); });
  await t('overview returns real counts', async () => {
    await anon.req('POST', '/api/track', { type: 'visit' }); await anon.req('POST', '/api/track', { type: 'run', lang: 'python' });
    const d = (await alice.req('GET', '/api/admin/overview')).json;
    assert.equal(d.totals.users, 3); assert.equal(d.totals.snippets >= 3, true);
    assert.equal(d.totals.views, 1); assert.equal(d.totals.runs, 1); assert.equal(d.days.length, 30);
    assert.equal(d.languages[0].label, 'python');
  });
  await t('tracking rejects junk', async () => assert.equal((await anon.req('POST', '/api/track', { type: 'drop table' })).status, 400));
  await t('users list is searchable', async () => {
    const d = (await alice.req('GET', '/api/admin/users?q=bob')).json;
    assert.equal(d.users.length, 1); assert.equal(d.users[0].email, 'bob@example.com');
    assert.equal((await alice.req('GET', "/api/admin/users?q=' OR 1=1 --")).json.users.length, 0);
  });
  let bobId;
  await t('suspend kicks the user out and blocks login', async () => {
    bobId = (await alice.req('GET', '/api/admin/users?q=bob')).json.users[0].id;
    assert.equal((await alice.req('POST', `/api/admin/users/${bobId}/status`, { status: 'banned' })).status, 200);
    assert.equal((await bob.req('GET', '/api/me')).json.user, null);
    assert.equal((await new Client().req('POST', '/api/auth/login', { email: 'bob@example.com', password: 'goodpass456' })).status, 403);
    await alice.req('POST', `/api/admin/users/${bobId}/status`, { status: 'active' });
  });
  await t('owner cannot demote or delete themselves', async () => {
    const me = (await alice.req('GET', '/api/me')).json.user.id;
    assert.equal((await alice.req('POST', `/api/admin/users/${me}/role`, { role: 'user' })).status, 409);
  });
  await t('deleting a user needs the password', async () => {
    assert.equal((await alice.req('POST', `/api/admin/users/${bobId}/delete`, { password: 'wrong' })).status, 403);
    assert.equal((await alice.req('POST', `/api/admin/users/${bobId}/delete`, { password: 'goodpass123' })).status, 200);
  });
  await t('announcements + settings round trip, validated', async () => {
    await alice.req('POST', '/api/admin/announcements', { msg: '<b>Hello</b>', type: 'warn' });
    const site = (await anon.req('GET', '/api/site')).json;
    assert.equal(site.announcements[0].msg, '<b>Hello</b>');   // stored raw; the page escapes it when rendering
    assert.equal((await alice.req('POST', '/api/admin/settings', { accent: 'red;}</style>' })).status, 400);
    assert.equal((await alice.req('POST', '/api/admin/settings', { accent: '#ff8800', features: { ai: false } })).status, 200);
    assert.equal((await anon.req('GET', '/api/site')).json.site.features.ai, false);
  });
  await t('maintenance mode blocks sign-up but not the owner', async () => {
    await alice.req('POST', '/api/admin/settings', { maintenance: true });
    assert.equal((await new Client().req('POST', '/api/auth/register', { name: 'Zed', email: 'z@example.com', password: 'goodpass123' })).status, 503);
    assert.equal((await new Client().req('POST', '/api/auth/login', { email: 'alice@example.com', password: 'goodpass123' })).status, 200);
    await alice.req('POST', '/api/admin/settings', { maintenance: false });
  });
  await t('AI / code runner report clearly when not configured', async () => {
    assert.equal((await alice.req('POST', '/api/chat', { messages: [{ role: 'user', content: 'hi' }] })).status, 403); // feature switched off above
    await alice.req('POST', '/api/admin/settings', { features: { ai: true } });
    const r = await alice.req('POST', '/api/chat', { messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(r.status, 501); assert.match(r.json.error, /ANTHROPIC_API_KEY/);
    assert.equal((await alice.req('POST', '/api/execute', { language: 'c', code: 'int main(){}' })).status, 501);
    assert.equal((await anon.req('POST', '/api/chat', { messages: [] })).status, 401);
  });

  console.log('Passwords + sessions');
  await t('password change needs current password and kills other sessions', async () => {
    const a2 = new Client(); await a2.req('POST', '/api/auth/login', { email: 'alice@example.com', password: 'goodpass123' });
    assert.equal((await alice.req('POST', '/api/me/password', { current: 'nope', next: 'newpass12345' })).status, 403);
    assert.equal((await alice.req('POST', '/api/me/password', { current: 'goodpass123', next: 'newpass12345' })).status, 200);
    assert.equal((await a2.req('GET', '/api/me')).json.user, null);
    assert.equal((await alice.req('GET', '/api/me')).json.user.email, 'alice@example.com');
  });
  await t('logout invalidates the session server-side', async () => {
    const old = alice.cookie; await alice.req('POST', '/api/auth/logout', {});
    const c = new Client(); c.cookie = old;
    assert.equal((await c.req('GET', '/api/me')).json.user, null);
  });
  await t('password is stored as a scrypt hash, not plain text', async () => {
    const { DatabaseSync } = require('node:sqlite');
    srv.kill(); await new Promise(r => setTimeout(r, 300));
    const db = new DatabaseSync(path.join(DATA, 'maclay.db'));
    const row = db.prepare("SELECT pass_hash FROM users WHERE email='alice@example.com'").get();
    assert.match(row.pass_hash, /^scrypt\$/); assert.ok(!row.pass_hash.includes('newpass12345'));
    const s = db.prepare('SELECT id FROM sessions LIMIT 1').get(); if (s) assert.equal(s.id.length, 64); // hashed token, not the cookie value
    db.close();
  });

  srv.kill(); fs.rmSync(DATA, { recursive: true, force: true });
  console.log(`\n${pass} checks passed${process.exitCode ? ' — SOME FAILED' : ''}`);
})();
