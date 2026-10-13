/* Runner: better-auth 1.7.1, generic OAuth plugin (OIDC discovery, PKCE, ID token verification), in-memory storage.
 * FIRST DRAFT - written without installing the library. Web contract: GET /start -> Keycloak ; the library's own
 * callback (/api/auth/callback/keycloak) -> redirect to /done ; GET /done -> result JSON.
 * Arguments: --port --issuer --client-id ; secret from RN_CLIENT_SECRET ; CA from NODE_EXTRA_CA_CERTS.
 * Corrected after reading the installed 1.7.1 package: sign-in is POST /api/auth/sign-in/social {provider, callbackURL};
 * the callback is /api/auth/callback/keycloak. getAccessToken / refreshToken take {accountId} (read from the installed schema), found via listUserAccounts. */
import http from 'node:http';
import { betterAuth } from 'better-auth';
import { genericOAuth, keycloak } from 'better-auth/plugins/generic-oauth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { createRequire } from 'node:module';

const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : d; };
const port = parseInt(arg('port', '3105'), 10);
const issuer = arg('issuer').replace(/\/$/, '');
const clientId = arg('client-id', 'rn-ba');
const base = `http://127.0.0.1:${port}`;
let version = '?';
try { version = createRequire(import.meta.url)('better-auth/package.json').version; } catch (e) { /* keep ? */ }

const db = { user: [], session: [], account: [], verification: [] };
const auth = betterAuth({
  baseURL: base, secret: 'runner-only-secret-runner-only-secret', database: memoryAdapter(db),
  // 1.7: the generic OAuth plugin registers providers into the core social endpoints (sign-in/social, callback/:id);
  // keycloak() is the library's own helper (discovery, PKCE on by default, ID token verified against JWKS with nonce).
  plugins: [genericOAuth({ config: [keycloak({ clientId, clientSecret: process.env.RN_CLIENT_SECRET || '', issuer })] })],
});

const b64 = (s) => { try { return JSON.parse(Buffer.from(String(s).split('.')[1], 'base64url').toString()); } catch (e) { return {}; } };
const shape = (v) => v == null ? 'absent' : /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(v) ? 'uuid' : /^[0-9a-f]{32}$/.test(v) ? 'hex32' : /^[A-Za-z0-9_-]{24}$/.test(v) ? 'base64-24' : `other(len=${String(v).length})`;

const toWeb = (req, extra = {}) => new Request(base + req.url, { method: req.method, headers: { ...req.headers, ...extra } });
async function send(res, r) {
  const headers = {};
  r.headers.forEach((v, k) => { if (k !== 'set-cookie') headers[k] = v; });
  const sc = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
  if (sc.length) headers['set-cookie'] = sc;
  res.writeHead(r.status, headers); res.end(Buffer.from(await r.arrayBuffer()));
}

http.createServer(async (req, res) => {
  try {
    if (req.url.startsWith('/start')) {
      const r = await auth.handler(new Request(base + '/api/auth/sign-in/social', { method: 'POST',
        headers: { 'content-type': 'application/json', origin: base }, body: JSON.stringify({ provider: 'keycloak', callbackURL: base + '/done' }) }));
      const j = await r.clone().json().catch(() => ({}));
      const sc = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      const loc = j.url || r.headers.get('location');
      if (!loc) {
        const txt = await r.clone().text().catch(() => '');
        res.writeHead(500); return res.end(`no authorization URL from better-auth: HTTP ${r.status} body=${txt.slice(0, 200)} api=${Object.keys(auth.api).filter((k) => /oauth|sign/i.test(k)).join(',')}`);
      }
      res.writeHead(302, { location: loc, ...(sc.length ? { 'set-cookie': sc } : {}) }); return res.end();
    }
    if (req.url.startsWith('/api/auth/')) return send(res, await auth.handler(toWeb(req)));
    if (req.url.startsWith('/done')) {
      const checks = []; const headers = new Headers({ cookie: req.headers.cookie || '' });
      const runner = { id: 'better-auth', language: 'node', library: 'better-auth', version };
      let tok = {};
      let sel = null, idc = {};
      try {
        const sess = await auth.api.getSession({ headers });
        // 1.7: getAccessToken / refreshToken no longer take {providerId}; they take the library's own account id
        // (or {useAccountCookie:true}), so the account is looked up first.
        const accts = await auth.api.listUserAccounts({ headers });
        const acct = (accts || []).find((a) => (a.providerId || a.provider) === 'keycloak');
        if (!acct) throw new Error('no keycloak account linked to the session');
        sel = { accountId: acct.id };
        tok = await auth.api.getAccessToken({ body: sel, headers });
        idc = b64(tok.idToken || '');
        const aud = [].concat(idc.aud || []);
        checks.push({ id: 'F1', status: 'done', observed: { token_obtained: !!tok.accessToken, session_created: !!(sess && sess.user),
          id_token_present: !!tok.idToken, issuer_matches: idc.iss === issuer, audience_ok: aud.includes(clientId) } });
      } catch (e) { checks.push({ id: 'F1', status: 'error', observed: {}, error: String((e && e.message) || e).slice(0, 300) }); }
      checks.push({ id: 'F4', status: tok.idToken ? 'done' : 'error', observed: { sid_format: shape(idc.sid) }, ...(tok.idToken ? {} : { error: 'no id token to inspect' }) });
      try {
        if (!sel) throw new Error('no account selected');
        const rr = await auth.api.refreshToken({ body: sel, headers });
        checks.push({ id: 'F2', status: 'done', observed: { refreshed: !!(rr && (rr.accessToken || rr.access_token)) } });
      } catch (e) { checks.push({ id: 'F2', status: 'error', observed: {}, error: String((e && e.message) || e).slice(0, 300) }); }
      res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ runner, checks, claims: {} }));
    }
    res.writeHead(404); res.end();
  } catch (e) { console.error(e); res.writeHead(500); res.end(String((e && e.stack) || e).slice(0, 400)); }
}).listen(port, '127.0.0.1');
