"""
sender_web.py  -  USER 1 (SENDER) WITH A WEB PAGE  (port 5002)

This is the SAME sender as sender.py (same 5 steps), but with buttons:
   [Register]  -> makes a new user with HIS OWN key pair
   [Send]      -> produce data, encrypt, sign, create JWT, save, send

Open it in the browser:  http://localhost:5002
The receiver is in another tab:  http://localhost:5003
"""

import os
import re
import json
import shutil
import requests
from flask import Flask, request, render_template_string

from crypto_utils import (
    generate_aes_key, aes_encrypt, wrap_aes_key, sign_data, create_jwt, b64e, get_certificate_role,
)
from registration import register_user, fetch_verified_public_key

# ---- settings (come from docker-compose, with default values) ----
RECEIVER_NAME = os.environ.get("RECEIVER_NAME", "receiver")
KEYS_DIR = os.environ.get("KEYS_DIR", "/app/keys")
DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
CA_URL = os.environ.get("CA_URL", "http://ca:5001")
RECEIVER_URL = os.environ.get("RECEIVER_URL", "http://receiver:5003")
CA_CERT_PATH = os.path.join(os.environ.get("TRUST_DIR", "/app/trust"), "ca_certificate.pem")
KEY_PASSWORD = os.environ.get("KEY_PASSWORD")
JWT_MINUTES = int(os.environ.get("JWT_MINUTES", "60"))

app = Flask(__name__)


def registered_users():
    """The users that already have keys + certificate in my keys folder."""
    if not os.path.isdir(KEYS_DIR):
        return []
    return sorted(
        name for name in os.listdir(KEYS_DIR)
        if os.path.exists(os.path.join(KEYS_DIR, name, "certificate.pem"))
    )


def roles_from_ca():
    """The current role of every user, as the CA says (the admin may have changed it)."""
    try:
        return requests.get(f"{CA_URL}/roles", timeout=5).json()
    except Exception:
        return {}


def users_with_roles():
    roles = roles_from_ca()
    return [f"{name} ({roles.get(name, '?')})" for name in registered_users()]


# ------------------------------------------------------------------
# REGISTER button: a new user gets HIS OWN key pair
# ------------------------------------------------------------------
def do_register(username, full_name, staff_id):
    log = []
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", username or ""):
        return ["Bad name. Use only letters, numbers, - and _ (max 32)."], False

    already = os.path.exists(os.path.join(KEYS_DIR, username, "private_key.pem"))
    try:
        register_user(username, KEYS_DIR, CA_URL, KEY_PASSWORD,
                      identity={"full_name": full_name, "staff_id": staff_id})
    except Exception as error:
        if not already:
            # the CA refused, so I delete the keys that I just made (they are useless)
            shutil.rmtree(os.path.join(KEYS_DIR, username), ignore_errors=True)
        return [f"Registration failed: {error}"], False

    if already:
        log.append(f"'{username}' already had keys. I loaded them (no new keys).")
    else:
        log.append(f"A NEW key pair was generated for '{username}'.")
        log.append(f"PRIVATE key (secret, encrypted with a password): sender_keys/{username}/private_key.pem")
        log.append(f"PUBLIC key (can be shared):                      sender_keys/{username}/public_key.pem")
    log.append("Only the PUBLIC key was sent to the CA (together with my full name and staff ID, for the admin).")
    log.append(f"Certificate received from the CA: sender_keys/{username}/certificate.pem")
    with open(os.path.join(KEYS_DIR, username, "certificate.pem"), "rb") as f:
        role = get_certificate_role(f.read())
    log.append(f"Status (role written by the CA in the certificate): {role}")
    if role == "pending":
        log.append("You are a NEW user. Your request is waiting for the admin's approval (http://localhost:5001/admin).")
        log.append("Please try to send again after the admin has decided.")
    elif role == "professor":
        log.append("You are an approved professor. You can send data now.")
    else:
        log.append(f"Your request was not approved (status: {role}).")
    return log, True


# ------------------------------------------------------------------
# SEND button: the same STEPs as sender.py
# ------------------------------------------------------------------
def do_send(username, record):
    log = []
    private_key = register_user(username, KEYS_DIR, CA_URL, KEY_PASSWORD)  # loads my keys

    # My status comes from my certificate. A new user is "pending": I do not even try to send.
    with open(os.path.join(KEYS_DIR, username, "certificate.pem"), "rb") as f:
        role = get_certificate_role(f.read())
    if role != "professor":
        if role == "pending":
            log.append("You are a NEW user. Your request is waiting for the admin's approval.")
            log.append("The admin decides here: http://localhost:5001/admin")
            log.append("Please try to send again after the admin has approved you.")
        else:
            log.append(f"Your request was not approved (status: {role}). You cannot send data.")
        return log, None

    # STEP 1 - PRODUCE THE DATA
    data = json.dumps(record, sort_keys=True)
    log.append("STEP 1 - PRODUCE THE DATA")
    log.append("         " + data)

    # STEP 2 - ENCRYPT THE DATA WITH AES (and lock the AES key with the receiver's public key)
    aes_key = generate_aes_key()
    nonce, encrypted_data = aes_encrypt(data, aes_key)
    receiver_public_key = fetch_verified_public_key(CA_URL, RECEIVER_NAME, CA_CERT_PATH, required_role="organization")
    encrypted_key = wrap_aes_key(aes_key, receiver_public_key)
    payload = {
        "sender": username,
        "receiver": RECEIVER_NAME,
        "nonce": b64e(nonce),
        "encrypted_data": b64e(encrypted_data),
        "encrypted_key": b64e(encrypted_key),
    }
    log.append("STEP 2 - ENCRYPT THE DATA WITH AES")
    log.append("         encrypted data: " + b64e(encrypted_data)[:50] + " ...")
    log.append("         the AES key was locked with the receiver's PUBLIC key (RSA-OAEP)")

    # STEP 3 - DIGITALLY SIGN THE DATA (my PRIVATE key)
    signature = sign_data(data, private_key)
    log.append("STEP 3 - DIGITALLY SIGN THE DATA")
    log.append("         signature: " + signature[:50] + " ...")

    # STEP 4 - CREATE THE JWT TOKEN
    token = create_jwt(private_key, username, RECEIVER_NAME, payload, JWT_MINUTES)
    log.append("STEP 4 - CREATE THE JWT TOKEN")
    log.append("         token: " + token[:50] + " ...")

    # STEP 5 - SAVE THE FILES
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, "record.json"), "w") as f:
        json.dump(record, f, indent=4)
    with open(os.path.join(DATA_DIR, "payload.json"), "w") as f:
        json.dump(payload, f, indent=4)
    with open(os.path.join(DATA_DIR, "signature.txt"), "w") as f:
        f.write(signature)
    with open(os.path.join(DATA_DIR, "token.jwt"), "w") as f:
        f.write(token)
    log.append("STEP 5 - SAVE THE FILES in sender_data/: record.json, payload.json, signature.txt, token.jwt")

    # SEND THE FILES to the receiver (another container)
    log.append(f"SEND THE FILES -> POST {RECEIVER_URL}/receive")
    answer = requests.post(
        f"{RECEIVER_URL}/receive",
        json={"payload": payload, "signature": signature, "token": token},
        timeout=20,
    ).json()
    return log, answer


PAGE = """
<!doctype html><title>Sender</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:30px auto;padding:0 16px;color:#222}
 .box{border:1px solid #ccc;border-radius:10px;padding:16px;margin:16px 0}
 label{display:block;margin:10px 0 3px;font-weight:600}
 input,select{padding:6px;font-size:15px;width:100%;box-sizing:border-box}
 button{margin-top:14px;padding:8px 18px;font-size:16px}
 .ok{background:#e6f6e6;border-color:#7c7}.bad{background:#fde8e8;border-color:#d77}
 pre{white-space:pre-wrap;background:#f6f6f6;padding:10px;border-radius:6px}
</style>
<h1>User 1 - Sender</h1>
<p>Registered users (role): <b>{{ users_roles | join(', ') if users_roles else 'none yet' }}</b></p>
<p>A new user is <b>pending</b> until the admin decides. The receiver accepts only a <b>professor</b>, approved by the admin at
 <a href="http://localhost:5001/admin" target="_blank">http://localhost:5001/admin</a>.</p>

<form class="box" method="post" action="/register">
 <h3>1. Register a new user (generate the key pair)</h3>
 <label>User name</label><input name="username" placeholder="for example: ali" required>
 <label>Full name</label><input name="full_name" placeholder="for example: Ali Rossi" required>
 <label>University staff ID (the admin compares it with the university records)</label>
 <input name="staff_id" placeholder="for example: PROF-2042" required>
 <button>Register and generate keys</button>
</form>

<form class="box" method="post" action="/send">
 <h3>2. Produce the data and send it</h3>
 <label>Send as user</label>
 <select name="username">{% for u in users %}<option {{ 'selected' if u == chosen }}>{{ u }}</option>{% endfor %}</select>
 <label>Student id</label><input name="student_id" value="STU-1024">
 <label>Course</label><input name="course" value="Data Security">
 <label>Grade</label><input name="grade" type="number" min="0" max="33" value="28">
 <label>Semester</label><input name="semester" value="2026">
 <button>Encrypt, sign and send</button>
</form>

{% if log %}
<div class="box {{ 'bad' if answer is defined and answer and not answer.valid else 'ok' if answer else '' }}">
 {% if answer %}<h2>Receiver answer: {{ 'VALID' if answer.valid else 'INVALID' }}</h2>
 <p>Authorized sender: {{ 'YES' if answer.authorized else 'NO' }} &nbsp;|&nbsp; Signature: {{ answer.signature_label }} &nbsp;|&nbsp;
    JWT token: {{ answer.jwt_label }}</p>
 {% if answer.reason %}<p>{{ answer.reason }}</p>{% endif %}{% endif %}
 <pre>{{ log | join('\\n') }}</pre>
</div>
{% endif %}
"""


@app.route("/")
def home():
    return render_template_string(PAGE, users=registered_users(), users_roles=users_with_roles(), log=None, chosen=None)


@app.route("/register", methods=["POST"])
def register_page():
    username = request.form.get("username", "").strip()
    log, ok = do_register(username, request.form.get("full_name", "").strip(), request.form.get("staff_id", "").strip())
    return render_template_string(PAGE, users=registered_users(), users_roles=users_with_roles(), log=log, answer=None, chosen=username if ok else None)


@app.route("/send", methods=["POST"])
def send_page():
    username = request.form.get("username", "")
    try:
        if not username:
            raise ValueError("please register a user first")
        try:
            grade = int(request.form.get("grade", ""))
        except ValueError:
            raise ValueError("the grade must be a number")
        record = {
            "student_id": request.form.get("student_id", ""),
            "course": request.form.get("course", ""),
            "grade": grade,
            "semester": request.form.get("semester", ""),
        }
        log, answer = do_send(username, record)
    except Exception as error:
        log, answer = [f"Error: {error}"], None
    return render_template_string(PAGE, users=registered_users(), users_roles=users_with_roles(), log=log, answer=answer, chosen=username)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
