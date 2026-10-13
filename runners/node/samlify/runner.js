'use strict';
/* Runner: samlify 2.13.1 as SAML service provider, Keycloak as IdP. FIRST DRAFT, written without installing the library.
 * Web contract: GET /start -> redirect to Keycloak (HTTP-Redirect AuthnRequest);  POST /acs -> result JSON.
 * Arguments: --port --issuer --client-id ; the IdP metadata is read from <issuer>/protocol/saml/descriptor ; CA from NODE_EXTRA_CA_CERTS.
 * Library defaults are kept on purpose (a team's first configuration). Assumptions to confirm on the first run:
 *   createLoginRequest(idp,'redirect') returns {id, context:<url>} ; parseLoginResponse(idp,'post',req) reads req.body ;
 *   extract.{response.inResponseTo, issuer, nameID, attributes} exist with the default templates. */
const express = require('express');
const saml = require('samlify');
const path = require('path');
const fs = require('fs');
const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : d; };
const port = parseInt(arg('port', '3103'), 10);
const issuer = arg('issuer').replace(/\/$/, '');
const clientId = arg('client-id', 'rn-saml-node');
const acs = `http://127.0.0.1:${port}/acs`;

let version = '?';
try { version = require('samlify/package.json').version; }
catch (e) { try { version = require(path.join(path.dirname(require.resolve('samlify')), '..', 'package.json')).version; } catch (e2) { /* keep ? */ } }

let validator = 'none (no-op, schema not validated)';
try { saml.setSchemaValidator(require('@authenio/samlify-node-xmllint')); validator = '@authenio/samlify-node-xmllint'; }
catch (e) { saml.setSchemaValidator({ validate: () => Promise.resolve('skipped') }); }

const app = express();
let idp, sp, pending = null;
async function init() {
  const r = await fetch(issuer + '/protocol/saml/descriptor');
  if (!r.ok) throw new Error('IdP descriptor HTTP ' + r.status);
  idp = saml.IdentityProvider({ metadata: await r.text() });
  // Keycloak's descriptor says WantAuthnRequestsSigned=true; samlify refuses to build a request that is not signed
  // (ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG), so the SP signs. The key pair is a TEST-ONLY pair kept next to this file;
  // its certificate is registered on the rn-saml-node client in the fx-runner realm.
  sp = saml.ServiceProvider({ entityID: clientId, authnRequestsSigned: true,
    privateKey: fs.readFileSync(path.join(__dirname, 'sp-test-key.pem')), signingCert: fs.readFileSync(path.join(__dirname, 'sp-test-cert.pem')),
    assertionConsumerService: [{ Binding: saml.Constants.namespace.binding.post, Location: acs }] });
}
const ready = init();

app.get('/start', async (req, res) => {
  try { await ready; const { id, context } = sp.createLoginRequest(idp, 'redirect'); pending = id; res.redirect(context); }
  catch (e) { console.error(e); res.status(500).json({ error: String((e && e.stack) || e).slice(0, 400) }); }
});
app.post('/acs', express.urlencoded({ extended: false }), async (req, res) => {
  const runner = { id: 'samlify', language: 'node', library: 'samlify', version };
  const checks = [];
  try {
    await ready;
    const r = await sp.parseLoginResponse(idp, 'post', req);
    const x = r.extract || {};
    const attrs = x.attributes || {};
    const nameId = x.nameID;
    checks.push({ id: 'S2', status: 'done', observed: { login_ok: true,
      in_response_to_matches: !!pending && ((x.response || {}).inResponseTo === pending),
      idp_issuer_matches: x.issuer === issuer || (Array.isArray(x.issuer) && x.issuer.includes(issuer)),
      schema_validator: validator } });
    checks.push({ id: 'S3', status: 'done', observed: { name_id_present: !!nameId, name_id_is_username: nameId === 'rn-user',
      username_attribute_present: attrs.username === 'rn-user' || (Array.isArray(attrs.username) && attrs.username.includes('rn-user')) } });
  } catch (e) {
    checks.push({ id: 'S2', status: 'error', observed: { schema_validator: validator }, error: String((e && e.message) || e).slice(0, 300) });
  }
  res.json({ runner, checks, claims: {} });
});
app.listen(port, '127.0.0.1');
