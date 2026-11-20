"""
ca_server.py  -  CERTIFICATE AUTHORITY + ADMIN PAGE (port 5001)

This is the "trusted third party". It does these things:
  1. Registers users: receives a PUBLIC key and returns a signed certificate.
     A new user gets the role "pending" (waiting for the admin).
  2. The receiving ORGANIZATION has a reserved name. It can only be registered
     with a secret that only the organization knows. Nobody else can become the receiver.
  3. The ADMIN (password protected page /admin) approves a user as "professor" or rejects him.
     To decide, the admin sees the FULL NAME and the university STAFF ID that the user gave
     at registration, and compares them with the university records (outside this system).
     A staff ID can be used by only one user.
     Only the CA can write a role, because the role is inside the certificate
     and the CA signs the certificate.
  4. Keeps all certificates in a public directory.

The CA PRIVATE key stays ONLY in this container (never in sender/receiver).
"""

import os
import re
import json
import html
import hmac
import shutil
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import quote

from flask import Flask, request, jsonify, Response, redirect

from crypto_utils import (
    create_ca, load_private_key, load_certificate, load_public_key_pem,
    issue_certificate, public_key_to_pem, get_certificate_role,
)

CA_DIR = os.environ.get("CA_DIR", "/app/ca_data")
TRUST_DIR = os.environ.get("TRUST_DIR", "/app/trust")
CERT_DIR = os.path.join(CA_DIR, "certificates")

# ---- settings (come from docker-compose) ----
ORGANIZATION_NAME = os.environ.get("ORGANIZATION_NAME", "receiver")        # the unique receiver
ORGANIZATION_SECRET = os.environ["ORGANIZATION_SECRET"]
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
RESERVED_NAMES = {ORGANIZATION_NAME, "admin", "ca"}
ROLES_THE_ADMIN_CAN_SET = ["professor", "rejected"]

os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(TRUST_DIR, exist_ok=True)

# create the CA the first time only
if not os.path.exists(os.path.join(CA_DIR, "ca_private_key.pem")):
    create_ca(CA_DIR)
    print("[CA] New Certificate Authority created.")

ca_key = load_private_key(os.path.join(CA_DIR, "ca_private_key.pem"))
with open(os.path.join(CA_DIR, "ca_certificate.pem"), "rb") as f:
    ca_cert = load_certificate(f.read())

# the CA certificate is PUBLIC. I copy it to the "trust" folder, so the other
# users have it already installed (like the root certificates inside a browser)
shutil.copy(os.path.join(CA_DIR, "ca_certificate.pem"), os.path.join(TRUST_DIR, "ca_certificate.pem"))

app = Flask(__name__)


def valid_name(username):
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,32}", username or ""))


def cert_path(username):
    return os.path.join(CERT_DIR, f"{username}.pem")


IDENTITY_FILE = os.path.join(CA_DIR, "identities.json")


def load_identities():
    try:
        with open(IDENTITY_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_identities(data):
    with open(IDENTITY_FILE, "w") as f:
        json.dump(data, f, indent=2)


def all_roles():
    """{user name: role} for every certificate that the CA issued."""
    roles = {}
    for file in sorted(os.listdir(CERT_DIR)):
        if file.endswith(".pem"):
            with open(os.path.join(CERT_DIR, file), "rb") as f:
                roles[file[:-4]] = get_certificate_role(f.read())
    return roles


@app.route("/health")
def health():
    return "ok"


# ------------------------------------------------------------------
# REGISTRATION: a user sends ONLY his public key
# ------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    body = request.json or {}
    username = body.get("username")
    public_key_pem = body.get("public_key", "").encode()
    secret = body.get("registration_secret") or ""

    if not valid_name(username):
        return jsonify(error="bad username"), 400

    # the name of the receiving organization is reserved: only the real organization
    # knows the secret. Other reserved names can never be registered.
    if username == ORGANIZATION_NAME:
        if not hmac.compare_digest(secret, ORGANIZATION_SECRET):
            print(f"[CA] REFUSED: somebody tried to register the reserved name '{username}'.", flush=True)
            return jsonify(error=f"the name '{username}' is reserved for the receiving organization"), 403
        role = "organization"
    elif username in RESERVED_NAMES:
        return jsonify(error=f"the name '{username}' is reserved"), 403
    else:
        role = "pending"   # everybody starts as pending; only the admin can approve a professor

    try:
        user_public_key = load_public_key_pem(public_key_pem)
    except Exception:
        return jsonify(error="bad public key"), 400

    # a name can have only ONE key. Nobody can register "sender" again with
    # another key (otherwise an attacker could steal the identity of the sender)
    if os.path.exists(cert_path(username)):
        with open(cert_path(username), "rb") as f:
            old = load_certificate(f.read())
        if public_key_to_pem(old.public_key()) != public_key_to_pem(user_public_key):
            return jsonify(error=f"'{username}' is already registered with another key"), 409
        return jsonify(certificate=open(cert_path(username)).read())   # keeps the current role

    # NEW user: the full name and the university staff ID help the admin to decide.
    # (A staff ID is used here, not the codice fiscale: a tax code is personal data and not needed.)
    full_name = (body.get("full_name") or "").strip()
    staff_id = (body.get("staff_id") or "").strip()
    if full_name and not re.fullmatch(r"[A-Za-z .'-]{2,60}", full_name):
        return jsonify(error="bad full name (letters, spaces, . ' - only)"), 400
    if staff_id and not re.fullmatch(r"[A-Za-z0-9-]{3,20}", staff_id):
        return jsonify(error="bad staff ID (3 to 20 letters, numbers or -)"), 400
    identities = load_identities()
    if staff_id and any(v.get("staff_id") == staff_id for v in identities.values()):
        print(f"[CA] REFUSED: staff ID '{staff_id}' is already used by another user.", flush=True)
        return jsonify(error=f"the staff ID '{staff_id}' is already used by another user"), 409
    if role == "pending":
        identities[username] = {"full_name": full_name or "not provided", "staff_id": staff_id or "not provided",
                                "registered_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
        save_identities(identities)

    cert_pem = issue_certificate(ca_key, ca_cert, username, user_public_key, role)
    with open(cert_path(username), "wb") as f:
        f.write(cert_pem)
    print(f"[CA] Certificate issued for '{username}' with the role '{role}'.", flush=True)
    return jsonify(certificate=cert_pem.decode())


@app.route("/certificate/<username>")
def get_certificate(username):
    if not valid_name(username):
        return jsonify(error="bad username"), 400
    if not os.path.exists(cert_path(username)):
        return jsonify(error="unknown user"), 404
    return Response(open(cert_path(username), "rb").read(), mimetype="application/x-pem-file")


@app.route("/users")
def users():
    return jsonify(sorted(all_roles()))


@app.route("/roles")
def roles():
    return jsonify(all_roles())


# ------------------------------------------------------------------
# ADMIN PAGE (password protected). Only the admin can approve a professor.
# ------------------------------------------------------------------
def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        ok = (auth is not None
              and hmac.compare_digest(auth.username or "", ADMIN_USER)
              and hmac.compare_digest(auth.password or "", ADMIN_PASSWORD))
        if not ok:
            return Response("Admin login required.", 401, {"WWW-Authenticate": 'Basic realm="CA admin"'})
        return function(*args, **kwargs)
    return wrapper


ADMIN_STYLE = """
<style>
 body{font-family:system-ui,sans-serif;max-width:820px;margin:30px auto;padding:0 16px;color:#2D2A3E}
 h1{color:#5B4B9A} .box{border-radius:10px;padding:14px 18px;margin:16px 0}
 .steps{background:#E9E3F8;border:1px solid #8B7BC8} .msg{background:#DAF2E7;border:1px solid #6DB89A}
 table{border-collapse:collapse;width:100%} th{background:#D9D0F2;text-align:left}
 td,th{border:1px solid #D5CFE8;padding:8px 10px}
 .badge{padding:2px 10px;border-radius:12px;font-weight:600}
 .pending{background:#FFF1C9} .professor{background:#DAF2E7} .organization{background:#DDEBFA} .rejected{background:#F9DDE5}
 button{padding:5px 12px;font-size:14px;cursor:pointer}
</style>
"""


@app.route("/admin")
@admin_required
def admin_page():
    def role_form(name_h, role, label):
        return (f'<form method="post" action="/admin/role" style="margin:0 4px 0 0;display:inline">'
                f'<input type="hidden" name="username" value="{name_h}">'
                f'<input type="hidden" name="role" value="{role}"><button>{label}</button></form>')
    order = {"pending": 0, "professor": 1, "rejected": 2, "organization": 3}
    identities = load_identities()
    rows = ""
    for name, role in sorted(all_roles().items(), key=lambda kv: (order.get(kv[1], 9), kv[0])):
        name_h, role_h = html.escape(name), html.escape(role)
        if name == ORGANIZATION_NAME:
            action = "fixed: the unique receiving organization"
        elif role == "pending":
            action = role_form(name_h, "professor", "Approve as professor") + role_form(name_h, "rejected", "Reject")
        elif role == "professor":
            action = role_form(name_h, "rejected", "Revoke approval")
        else:
            action = role_form(name_h, "professor", "Approve as professor")
        status = {"pending": "waiting for approval", "professor": "approved", "rejected": "rejected"}.get(role, "")
        who = identities.get(name, {})
        full_h = html.escape(who.get("full_name", "-"))
        staff_h = html.escape(who.get("staff_id", "-"))
        rows += (f'<tr><td>{name_h}</td><td>{full_h}</td><td>{staff_h}</td>'
                 f'<td><span class="badge {role_h}">{role_h}</span> {status}</td><td>{action}</td></tr>')
    message = request.args.get("msg", "")
    message_html = f'<div class="box msg">{html.escape(message)}</div>' if message else ""
    return f"""<!doctype html><title>CA admin</title>{ADMIN_STYLE}
<h1>Admin control page - Certificate Authority</h1>
<div class="box steps"><b>How it works</b>
<ol>
 <li>A new user registers and his request is <b>pending</b>. He cannot send data yet.</li>
 <li>The admin compares the <b>full name</b> and the <b>staff ID</b> of the request with the university records (outside this system) and clicks <b>Approve as professor</b> or <b>Reject</b>.</li>
 <li>The CA signs a new certificate with the new role.</li>
 <li>The user tries again. The receiver accepts a record only from a user whose certificate says <b>professor</b>.</li>
</ol></div>
{message_html}
<table><tr><th>User</th><th>Full name</th><th>Staff ID</th><th>Role in the certificate</th><th>Admin action</th></tr>{rows or '<tr><td colspan=5>No users yet.</td></tr>'}</table>
<p>The receiving organization is <b>{html.escape(ORGANIZATION_NAME)}</b>. It is unique: its name is reserved and can only be registered with a secret.</p>
"""


@app.route("/admin/role", methods=["POST"])
@admin_required
def admin_set_role():
    username = request.form.get("username", "")
    role = request.form.get("role", "")
    if not valid_name(username) or not os.path.exists(cert_path(username)):
        return redirect("/admin?msg=" + quote("Unknown user."))
    if username == ORGANIZATION_NAME or role not in ROLES_THE_ADMIN_CAN_SET:
        return redirect("/admin?msg=" + quote("This change is not allowed."))

    # the CA issues a NEW certificate for the same public key, with the new role
    with open(cert_path(username), "rb") as f:
        old = load_certificate(f.read())
    new_pem = issue_certificate(ca_key, ca_cert, username, old.public_key(), role)
    with open(cert_path(username), "wb") as f:
        f.write(new_pem)
    print(f"[CA] ADMIN changed the role of '{username}' to '{role}'.", flush=True)
    return redirect("/admin?msg=" + quote(f"'{username}' now has the role '{role}'."))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
