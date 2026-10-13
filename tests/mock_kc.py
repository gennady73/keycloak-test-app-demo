"""Tiny mock of the Keycloak endpoints the Phase 0 tool reads. Test use only."""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
PORT = int(sys.argv[1]); SECRET = "S3CRET-VALUE-xyz"
CLIENTS = [
 {"id":"1","clientId":"good-app","protocol":"openid-connect","publicClient":False,"secret":SECRET,
  "redirectUris":["https://app.example.org/*"],"webOrigins":["https://app.example.org"],"attributes":{}},
 {"id":"2","clientId":"old-wildcards","protocol":"openid-connect","secret":SECRET,"registrationAccessToken":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk",
  "redirectUris":["https://*.example.org/*","https://host.example.org*","https://a.example.org/cb?state=1"],
  "webOrigins":["https://a.example.org/","+"],"clientAuthenticatorType":"client-jwt",
  "attributes":{"post.logout.redirect.uris":"http://a.example.org/out##https://a.example.org/out2",
   "allow.oidc.params.in.redirect.uris":"true","standard.token.exchange.enabled":"true",
   "jwt.credential.certificate":"MIIB...","client.secret.creation.time":"1700000000","logoUri":"http://a/logo.png"}},
]
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def send(self,code,obj):
        b=json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length",0)))
        self.send(200,{"access_token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig"})
    def do_GET(self):
        p=self.path.split("?")[0]; base="http://127.0.0.1:%d"%PORT
        if p=="/admin/serverinfo": return self.send(200,{"systemInfo":{"version":"26.6.6"}})
        if p=="/admin/realms": return self.send(200,[{"realm":"master"},{"realm":"corp"}])
        if p=="/admin/realms/corp": return self.send(200,{"realm":"corp","sslRequired":"external"})
        if p=="/admin/realms/corp/clients":
            q=self.path.split("?")[1]; first=int(dict(x.split("=") for x in q.split("&"))["first"])
            return self.send(200,CLIENTS[first:first+100])
        if p.endswith("client-policies/profiles"): return self.send(200,{"profiles":[{"name":"x","executors":[{"executor":"secure-client-uris"}]}]})
        if p.endswith("identity-provider/instances"): return self.send(200,[{"alias":"idp","providerId":"oidc","config":{"clientSecret":"**","jwksUrl":"https://idp/jwks","issuer":"https://idp"}}])
        if p=="/realms/corp/.well-known/openid-configuration":
            return self.send(200,{"issuer":base+"/realms/corp","authorization_endpoint":"http://other-host:8443/realms/corp/auth","token_endpoint":base+"/t"})
        if p.startswith("/.well-known/oauth-authorization-server"): return self.send(404,{})
        if p=="/health/ready": return self.send(503,{})
        self.send(404,{})
HTTPServer(("127.0.0.1",PORT),H).serve_forever()
