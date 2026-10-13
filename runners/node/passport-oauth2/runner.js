'use strict';
/* Runner: passport-oauth2 (generic OAuth2, no OIDC discovery, no ID token validation).
 * First draft - written without being able to install the library. Web contract:
 *   GET /start    -> redirect to Keycloak       GET /callback -> result JSON (runner contract, see rn_common.py)
 * Arguments: --port --issuer --client-id ; secret from RN_CLIENT_SECRET ; CA from NODE_EXTRA_CA_CERTS.
 * Used the way a team typically uses it: URLs configured by hand, state + PKCE on, tokens read from verify().
 * What the library does NOT do (and the runner therefore checks itself, like an application would have to):
 * ID token signature, issuer and audience validation, nonce. */
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const libVersion = require('passport-oauth2/package.json').version;

const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : d; };
const port = parseInt(arg('port', '3101'), 10);
const issuer = arg('issuer').replace(/\/$/, '');
const clientId = arg('client-id', 'rn-node');
const secret = process.env.RN_CLIENT_SECRET || '';
const oidc = issuer + '/protocol/openid-connect';
const callbackURL = `http://127.0.0.1:${port}/callback`;

const b64 = (s) => { try { return JSON.parse(Buffer.from(s.split('.')[1], 'base64url').toString()); } catch (e) { return {}; } };
const shape = (v) => v == null ? 'absent' : /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(v) ? 'uuid' : /^[0-9a-f]{32}$/.test(v) ? 'hex32' : /^[A-Za-z0-9_-]{24}$/.test(v) ? 'base64-24' : `other(len=${String(v).length})`;
const safe = (c) => { const o = {}; for (const k of ['iss', 'aud', 'azp', 'typ', 'exp', 'iat', 'auth_time', 'acr', 'scope']) if (k in c) o[k] = c[k]; o.has_sub = 'sub' in c; if ('sid' in c) o.sid_format = shape(c.sid); return o; };

const strategy = new OAuth2Strategy(
  { authorizationURL: oidc + '/auth', tokenURL: oidc + '/token', clientID: clientId, clientSecret: secret,
    callbackURL, scope: ['openid'], state: true, pkce: true },
  (accessToken, refreshToken, params, profile, done) => done(null, { accessToken, refreshToken, params }));
passport.use('oauth2', strategy);

const app = express();
app.use(session({ secret: 'runner-only', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.get('/start', passport.authenticate('oauth2', { session: false }));
app.get('/callback', (req, res, next) => {
  passport.authenticate('oauth2', { session: false }, async (err, user) => {
    const checks = []; const claims = {};
    const out = () => res.json({ runner: { id: 'passport-oauth2', language: 'node', library: 'passport-oauth2', version: libVersion }, checks, claims });
    if (err || !user) { checks.push({ id: 'F1', status: 'error', observed: {}, error: String((err && (err.message || JSON.stringify(err.data || err))) || 'authentication failed') }); return out(); }
    const idc = b64(user.params.id_token || '');
    claims.id_token = safe(idc); claims.access_token = safe(b64(user.accessToken));
    const aud = [].concat(idc.aud || []);
    checks.push({ id: 'F1', status: 'done', observed: { token_obtained: !!user.accessToken, id_token_present: !!user.params.id_token,
      issuer_matches: idc.iss === issuer, audience_ok: aud.includes(clientId), refresh_token_issued: !!user.refreshToken } });
    checks.push({ id: 'F4', status: 'done', observed: { sid_format: shape(idc.sid), session_state_format: shape(user.params.session_state) } });
    await new Promise((resolve) => {
      if (!user.refreshToken) { checks.push({ id: 'F2', status: 'error', observed: {}, error: 'no refresh token issued' }); return resolve(); }
      // passport-oauth2 has no refresh API of its own; applications call the underlying 'oauth' client.
      strategy._oauth2.getOAuthAccessToken(user.refreshToken, { grant_type: 'refresh_token' }, (e, at, rt) =>
        { checks.push(e ? { id: 'F2', status: 'error', observed: { http_status: e.statusCode }, error: 'refresh failed' }
                        : { id: 'F2', status: 'done', observed: { refreshed: !!at, new_refresh_token: !!rt } }); resolve(); });
    });
    out();
  })(req, res, next);
});
app.listen(port, '127.0.0.1');
