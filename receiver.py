"""
receiver.py  -  USER 2 (RECEIVER)  - an independent server (port 5003)

It follows the second half of the diagram:

   Load the received files and the public key, and check the ROLE of the sender
   (only an approved PROFESSOR is accepted)
   Decrypt the data
   Verify the digital signature
   Check the JWT token            (identity, for me, not expired, used only once)
   -> VALID / INVALID

You can use it in TWO ways:
  1. automatic : the sender sends the files to  POST /receive
  2. by hand   : open http://localhost:5003 in the browser, pick the files
                 and the public key, and click "Verify"

It also uses a MongoDB database with 2 collections:
  - seen_tokens : the jti of every token that I already accepted (anti-replay)
  - log         : the history of every message I received (VALID or INVALID)
"""

import os
import json
import time
from datetime import datetime, timezone

from pymongo import MongoClient, errors
from flask import Flask, request, jsonify, render_template_string

from crypto_utils import (
    unwrap_aes_key, aes_decrypt, verify_signature, load_public_key_pem, b64d,
    verify_jwt, payload_fingerprint, public_key_to_pem,
)
from registration import register_user, fetch_verified_certificate

# ---- settings ----
USER_NAME = os.environ.get("USER_NAME", "receiver")
KEYS_DIR = os.environ.get("KEYS_DIR", "/app/keys")
DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
CA_URL = os.environ.get("CA_URL", "http://ca:5001")
CA_CERT_PATH = os.path.join(os.environ.get("TRUST_DIR", "/app/trust"), "ca_certificate.pem")
KEY_PASSWORD = os.environ.get("KEY_PASSWORD")
ORGANIZATION_SECRET = os.environ["ORGANIZATION_SECRET"]
RECEIVED_DIR = os.path.join(DATA_DIR, "received")
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://mongo:27017")
os.makedirs(RECEIVED_DIR, exist_ok=True)


# ------------------------------------------------------------------
# DATABASE (MongoDB): runs in its own container called "mongo"
# ------------------------------------------------------------------
mongo = MongoClient(MONGO_URL, serverSelectionTimeoutMS=3000)

# MongoDB may start a few seconds later than me, so I wait until it answers
for _ in range(30):
    try:
        mongo.admin.command("ping")
        break
    except errors.PyMongoError:
        time.sleep(1)

database = mongo["secure_certificate"]
seen_tokens = database["seen_tokens"]   # collection 1: tokens that I already accepted
log_collection = database["log"]        # collection 2: history of all received messages

# unique index on jti: MongoDB itself refuses the same token number twice
seen_tokens.create_index("jti", unique=True)


def now_text():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# REGISTER: the receiver also has HIS OWN key pair (different from the sender).
# I am the unique receiving ORGANIZATION: my name is reserved at the CA, and I can only
# register it with the secret that only I know. A hacker cannot become the receiver.
print("RECEIVER - generate my key pair and register as the organization", flush=True)
my_private_key = register_user(USER_NAME, KEYS_DIR, CA_URL, KEY_PASSWORD, ORGANIZATION_SECRET)

app = Flask(__name__)


# ------------------------------------------------------------------
# The main work. Used by the automatic way AND by the web page.
# manual=True means "web page": I do not use the database (no replay check)
# and I do not enforce the expiry time, so old files can still be shown in a demo.
# ------------------------------------------------------------------
def check_files(payload, signature, token, public_key_pem=None, manual=False):
    steps = []
    result = {
        "valid": False, "authorized": False, "signature_valid": False, "jwt_valid": False,
        "role": "?", "stage": 0, "reason": "", "record": None, "steps": steps,
    }

    def log(text):
        steps.append(text)
        print(text, flush=True)

    # STEP 1 - LOAD THE RECEIVED FILES AND THE PUBLIC KEY, AND CHECK THE ROLE OF THE SENDER
    # I ask the CA for the certificate of the sender and I CHECK it before I trust it.
    # The ROLE comes from this certificate (the CA signed it). It never comes from the package.
    try:
        sender_name = payload["sender"]
        log(f"STEP 1 - Files loaded (payload, signature, token). The sender is '{sender_name}'.")

        ca_public_key, role = fetch_verified_certificate(CA_URL, sender_name, CA_CERT_PATH)
        result["role"] = role
        if public_key_pem:
            # the user picked a public key file by hand
            sender_public_key = load_public_key_pem(public_key_pem)
            log("         Public key: the file that was picked by hand.")
        else:
            sender_public_key = ca_public_key
            log("         Public key: taken from the CA certificate (CA signature checked).")
    except Exception as error:
        result["reason"] = f"could not load files or public key ({error})"
        log("         " + result["reason"])
        return result

    # AUTHORIZATION: only an approved professor may send grades.
    if role != "professor":
        result["reason"] = f"sender '{sender_name}' is not an approved professor (role in the certificate: {role})"
        log("         Authorization: REJECTED (" + result["reason"] + ")")
        return result
    result["authorized"] = True
    result["stage"] = 1
    log("         Authorization: OK (the CA certificate says: role professor)")

    # STEP 2 - DECRYPT THE DATA
    # (a) my PRIVATE key opens the locked AES key
    # (b) the AES key decrypts the data
    # If somebody changed the encrypted data, AES-GCM refuses to decrypt.
    try:
        aes_key = unwrap_aes_key(b64d(payload["encrypted_key"]), my_private_key)
        data = aes_decrypt(b64d(payload["nonce"]), b64d(payload["encrypted_data"]), aes_key)
        result["record"] = json.loads(data)
        result["stage"] = 2
        log("STEP 2 - Data decrypted (my private key -> AES key -> data).")
        log("         Decrypted record: " + data)
    except Exception:
        result["reason"] = "decryption failed: the data was changed or it is not for me"
        log("STEP 2 - " + result["reason"])
        return result

    # STEP 3 - VERIFY THE DIGITAL SIGNATURE
    # I check the signature against the decrypted data with the sender's PUBLIC key.
    if verify_signature(data, signature, sender_public_key):
        result["signature_valid"] = True
        result["stage"] = 3
        log("STEP 3 - Digital signature: VALID   (data is authentic, nobody changed it)")
    else:
        result["reason"] = "the signature does not match this data (tampering or wrong sender)"
        log("STEP 3 - Digital signature: INVALID (" + result["reason"] + ")")
        return result

    # STEP 4 - CHECK THE JWT TOKEN
    # (a) the token signature is real (made by the sender's private key)
    # (b) issuer = the sender, audience = me, and it is not expired
    # (c) the token belongs to THIS payload (the fingerprint is the same)
    # (d) the token was NOT used before (anti-replay, I check my MongoDB)
    try:
        claims = verify_jwt(token, sender_public_key, sender_name, USER_NAME, check_exp=not manual)
        if claims["payload_hash"] != payload_fingerprint(payload):
            raise ValueError("this token belongs to another payload")

        if not manual:
            # I save the token number. If it is already there, MongoDB refuses = replay
            try:
                seen_tokens.insert_one({"jti": claims["jti"], "issuer": sender_name, "seen_at": now_text()})
            except errors.DuplicateKeyError:
                raise ValueError("this token was already used (replay attack)")

        result["jwt_valid"] = True
        if manual:
            log("STEP 4 - JWT token: VALID   (right sender, for me, same payload; expiry and replay are not checked in manual mode)")
        else:
            log("STEP 4 - JWT token: VALID   (right sender, for me, not expired, first use)")
    except Exception as error:
        result["reason"] = f"JWT token problem: {error}"
        log("STEP 4 - JWT token: INVALID (" + str(error) + ")")
        return result

    result["valid"] = True
    log("RESULT  - VALID")
    return result


def add_labels(result):
    """Text for the answer. A check that was never reached says "not checked", not "INVALID"."""
    def label(ok, reached):
        return "VALID" if ok else ("INVALID" if reached else "not checked")
    result["signature_label"] = label(result["signature_valid"], result["stage"] >= 2)
    result["jwt_label"] = label(result["jwt_valid"], result["stage"] >= 3)
    return result


# ------------------------------------------------------------------
# AUTOMATIC WAY: the sender posts the files here
# ------------------------------------------------------------------
@app.route("/receive", methods=["POST"])
def receive():
    body = request.get_json()
    payload, signature, token = body["payload"], body["signature"], body["token"]

    print("\n" + "=" * 60)
    print("USER 2 - RECEIVER: files received from the network")
    print("=" * 60, flush=True)

    # I save the received files, so I can show them
    with open(os.path.join(RECEIVED_DIR, "payload.json"), "w") as f:
        json.dump(payload, f, indent=4)
    with open(os.path.join(RECEIVED_DIR, "signature.txt"), "w") as f:
        f.write(signature)
    with open(os.path.join(RECEIVED_DIR, "token.jwt"), "w") as f:
        f.write(token)

    result = add_labels(check_files(payload, signature, token))

    # I write the history in the database
    log_collection.insert_one({
        "time": now_text(), "sender": payload.get("sender", "?"), "role": result["role"],
        "valid": result["valid"], "reason": result["reason"],
    })

    return jsonify(result)


@app.route("/public-key")
def public_key():
    return public_key_to_pem(my_private_key.public_key()), 200, {"Content-Type": "application/x-pem-file"}


# ------------------------------------------------------------------
# BY HAND WAY: the web page
# ------------------------------------------------------------------
PAGE = """
<!doctype html><title>Receiver</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:30px auto;padding:0 16px;color:#222}
 .box{border:1px solid #ccc;border-radius:10px;padding:16px;margin:16px 0}
 label{display:block;margin:10px 0 3px;font-weight:600}
 button{margin-top:14px;padding:8px 18px;font-size:16px}
 .ok{background:#e6f6e6;border-color:#7c7}.bad{background:#fde8e8;border-color:#d77}
 pre{white-space:pre-wrap;background:#f6f6f6;padding:10px;border-radius:6px}
 table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px;text-align:left;font-size:14px}
</style>
<h1>User 2 - Receiver</h1>
<p>Independent server. Load the received files and the public key, then verify.</p>

<form class="box" method="post" action="/verify" enctype="multipart/form-data">
 <label>1. payload.json</label><input type="file" name="payload" required>
 <label>2. signature.txt</label><input type="file" name="signature" required>
 <label>3. token.jwt</label><input type="file" name="token" required>
 <label>4. Sender public key (.pem) - optional, if empty I ask the CA</label>
 <input type="file" name="public_key">
 <button>Decrypt and verify</button>
</form>

{% if result %}
<div class="box {{ 'ok' if result.valid else 'bad' }}">
 <h2>{{ 'VALID' if result.valid else 'INVALID' }}</h2>
 <p>Authorized sender: {{ 'YES' if result.authorized else 'NO' }} &nbsp;|&nbsp; Signature: {{ result.signature_label }} &nbsp;|&nbsp;
    JWT token: {{ result.jwt_label }}</p>
 {% if result.reason %}<p>{{ result.reason }}</p>{% endif %}
 {% if result.record %}<p>Decrypted record:</p><pre>{{ result.record | tojson(indent=2) }}</pre>{% endif %}
 <p>Steps:</p><pre>{{ result.steps | join('\\n') }}</pre>
</div>
{% endif %}

<div class="box">
 <h3>History of received messages (MongoDB)</h3>
 {% if rows %}
 <table><tr><th>Time</th><th>Sender</th><th>Role</th><th>Result</th><th>Reason</th></tr>
 {% for r in rows %}<tr><td>{{ r[0] }}</td><td>{{ r[1] }}</td><td>{{ r[2] }}</td>
  <td>{{ 'VALID' if r[3] else 'INVALID' }}</td><td>{{ r[4] }}</td></tr>{% endfor %}
 </table>
 {% else %}<p>No messages yet.</p>{% endif %}
</div>
"""


def history():
    last = log_collection.find().sort("_id", -1).limit(10)
    return [(d["time"], d["sender"], d.get("role", "?"), d["valid"], d["reason"]) for d in last]


@app.route("/")
def home():
    return render_template_string(PAGE, result=None, rows=history())


@app.route("/verify", methods=["POST"])
def verify_page():
    try:
        payload = json.load(request.files["payload"])
        signature = request.files["signature"].read().decode()
        token = request.files["token"].read().decode()
        key_file = request.files.get("public_key")
        key_pem = key_file.read() if key_file and key_file.filename else None
        result = add_labels(check_files(payload, signature, token, key_pem, manual=True))
    except Exception as error:
        result = add_labels({"valid": False, "authorized": False, "signature_valid": False, "jwt_valid": False,
                  "role": "?", "stage": 0, "reason": f"bad files ({error})", "record": None, "steps": []})
    return render_template_string(PAGE, result=result, rows=history())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
