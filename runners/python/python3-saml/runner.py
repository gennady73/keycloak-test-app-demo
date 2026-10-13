#!/usr/bin/env python3
"""Runner: python3-saml 1.16.0 as SAML service provider, Keycloak as IdP. FIRST DRAFT (library not installed where written).
Web contract: GET /start -> Keycloak ; POST /acs -> result JSON. Arguments: --port --issuer --client-id ; CA via --ca-bundle.
Library defaults are kept, strict mode on. Assumptions to confirm on the first run: IdPMetadataParser.parse(xml) returns
{'idp': {...}} usable in settings; auth.login() returns the redirect URL; process_response(request_id=...) validates InResponseTo."""
import argparse, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from rn_common import Http

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=3104); ap.add_argument("--issuer", required=True)
ap.add_argument("--client-id", default="rn-saml-py"); ap.add_argument("--ca-bundle")
a = ap.parse_args()
iss, host = a.issuer.rstrip("/"), "127.0.0.1:%d" % a.port

from flask import Flask, jsonify, redirect, request                       # noqa: E402
from onelogin.saml2.auth import OneLogin_Saml2_Auth                       # noqa: E402
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser   # noqa: E402
import importlib.metadata as md                                           # noqa: E402

st, _, xml = Http(a.ca_bundle).get(iss + "/protocol/saml/descriptor")
if st != 200:
    sys.exit("IdP descriptor HTTP %s" % st)
idp = OneLogin_Saml2_IdPMetadataParser.parse(xml.decode("utf-8"))["idp"]
settings = {"strict": True, "debug": False,
            "sp": {"entityId": a.client_id, "assertionConsumerService": {"url": "http://%s/acs" % host,
                   "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}},
            "idp": idp}
state = {}
app = Flask(__name__)


def req_dict():
    return {"https": "off", "http_host": host, "script_name": request.path, "get_data": request.args.copy(), "post_data": request.form.copy()}


@app.route("/start")
def start():
    auth = OneLogin_Saml2_Auth(req_dict(), settings)
    url = auth.login()
    state["id"] = auth.get_last_request_id()
    return redirect(url)


@app.route("/acs", methods=["POST"])
def acs():
    runner = dict(id="python3-saml", language="python", library="python3-saml", version=md.version("python3-saml"))
    auth = OneLogin_Saml2_Auth(req_dict(), settings)
    try:
        auth.process_response(request_id=state.get("id"))
    except Exception as e:  # noqa: BLE001
        return jsonify(runner=runner, claims={}, checks=[dict(id="S2", status="error", observed={}, error=str(e)[:300])])
    errors = auth.get_errors()
    if errors:
        return jsonify(runner=runner, claims={}, checks=[dict(id="S2", status="error", observed={"errors": errors},
                       error=str(auth.get_last_error_reason() or errors)[:300])])
    nid, attrs = auth.get_nameid(), auth.get_attributes()
    return jsonify(runner=runner, claims={}, checks=[
        dict(id="S2", status="done", observed=dict(login_ok=auth.is_authenticated(), in_response_to_matches=True)),
        dict(id="S3", status="done", observed=dict(name_id_present=bool(nid), name_id_is_username=nid == "rn-user",
                                                     username_attribute_present="rn-user" in (attrs.get("username") or [])))])


app.run(host="127.0.0.1", port=a.port)
