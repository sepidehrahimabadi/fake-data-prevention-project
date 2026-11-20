"""
sender.py  -  USER 1 (SENDER)

This program follows the diagram of the project:

   Register + generate key pair
   1. Produce the data
   2. Encrypt the data with AES
   3. Digitally sign the data
   4. Create the JWT token        (the project title says JWT, so it is here)
   5. Save JSON / payload / signature / token
   -> Send the files to the receiver (another independent environment)

Run it with:   docker compose run --rm sender
Run it as another user:   docker compose run --rm -e USER_NAME=ali -e FULL_NAME="Ali Rossi" -e STAFF_ID=PROF-2042 sender
"""

import os
import sys
import json
import requests

from crypto_utils import (
    generate_aes_key, aes_encrypt, wrap_aes_key, sign_data, create_jwt, b64e, get_certificate_role,
)
from registration import register_user, fetch_verified_public_key

# ---- settings (come from docker-compose, with default values) ----
USER_NAME = os.environ.get("USER_NAME", "sender")
RECEIVER_NAME = os.environ.get("RECEIVER_NAME", "receiver")
KEYS_DIR = os.environ.get("KEYS_DIR", "/app/keys")
DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
CA_URL = os.environ.get("CA_URL", "http://ca:5001")
RECEIVER_URL = os.environ.get("RECEIVER_URL", "http://receiver:5003")
CA_CERT_PATH = os.path.join(os.environ.get("TRUST_DIR", "/app/trust"), "ca_certificate.pem")
KEY_PASSWORD = os.environ.get("KEY_PASSWORD")
FULL_NAME = os.environ.get("FULL_NAME")        # only needed at the first registration
STAFF_ID = os.environ.get("STAFF_ID")          # university staff ID, the admin checks it
JWT_MINUTES = int(os.environ.get("JWT_MINUTES", "60"))  # life of the token


def title(text):
    print()
    print("=" * 60)
    print(text)
    print("=" * 60)


title(f"USER 1 - SENDER ({USER_NAME})")

# ------------------------------------------------------------------
# REGISTER: make my own key pair and get my certificate from the CA
# ------------------------------------------------------------------
print("\nREGISTER - generate my key pair")
my_private_key = register_user(USER_NAME, KEYS_DIR, CA_URL, KEY_PASSWORD,
                               identity={"full_name": FULL_NAME, "staff_id": STAFF_ID})

# The CA wrote my ROLE inside my certificate. A NEW user is "pending" until the admin decides.
with open(os.path.join(KEYS_DIR, USER_NAME, "certificate.pem"), "rb") as f:
    my_role = get_certificate_role(f.read())
print(f"My status (the role that the CA wrote in my certificate): {my_role}")
if my_role == "pending":
    print("\nYou are a NEW user. Your request is waiting for the admin's approval.")
    print("The admin decides here:  http://localhost:5001/admin")
    print("Please run the sender again after the admin has approved you.")
    sys.exit(0)
if my_role != "professor":
    print(f"\nYour request was not approved (status: {my_role}). You cannot send data.")
    sys.exit(0)

# ------------------------------------------------------------------
# STEP 1 - PRODUCE THE DATA
# This is the academic record that I want to send.
# ------------------------------------------------------------------
record = {
    "student_id": "STU-1024",
    "course": "Data Security",
    "grade": 28,
    "semester": "2026",
}

# I convert the record to a JSON text. sort_keys=True keeps the same order
# every time, so the sender and the receiver see exactly the same text.
data = json.dumps(record, sort_keys=True)

print("\nSTEP 1 - PRODUCE THE DATA")
print(data)

# ------------------------------------------------------------------
# STEP 2 - ENCRYPT THE DATA WITH AES
# (a) make a new random AES key
# (b) encrypt the data with the AES key
# (c) lock the AES key with the RECEIVER's PUBLIC key (RSA), taken from the CA
#     -> only the receiver's PRIVATE key can open it
# ------------------------------------------------------------------
aes_key = generate_aes_key()
nonce, encrypted_data = aes_encrypt(data, aes_key)

# I only send to the real receiving ORGANIZATION: its certificate must say role "organization".
# This way a hacker cannot pretend to be the receiver.
try:
    receiver_public_key = fetch_verified_public_key(CA_URL, RECEIVER_NAME, CA_CERT_PATH, required_role="organization")
except RuntimeError as error:
    print("\nSTOP - I will not send my data to this receiver:", error)
    sys.exit(1)
encrypted_key = wrap_aes_key(aes_key, receiver_public_key)

# the payload is the "package" with everything that is encrypted
payload = {
    "sender": USER_NAME,
    "receiver": RECEIVER_NAME,
    "nonce": b64e(nonce),
    "encrypted_data": b64e(encrypted_data),
    "encrypted_key": b64e(encrypted_key),
}

print("\nSTEP 2 - ENCRYPT THE DATA WITH AES")
print("Encrypted data (first 60 chars):", b64e(encrypted_data)[:60], "...")
print("The AES key was locked with the receiver's public key (RSA-OAEP).")

# ------------------------------------------------------------------
# STEP 3 - DIGITALLY SIGN THE DATA
# I sign the data with MY PRIVATE key. The result is the signature.
# Only I can create it, everybody can check it with my public key.
# ------------------------------------------------------------------
signature = sign_data(data, my_private_key)

print("\nSTEP 3 - DIGITALLY SIGN THE DATA")
print("Signature created with my PRIVATE key (first 60 chars):", signature[:60], "...")

# ------------------------------------------------------------------
# STEP 4 - CREATE THE JWT TOKEN
# The JWT is a small signed ticket. It says: "I am <sender>, this is for
# <receiver>, valid until <time>, ticket number <jti>, for THIS payload".
# I sign it with my PRIVATE key (RS256).
# ------------------------------------------------------------------
token = create_jwt(my_private_key, USER_NAME, RECEIVER_NAME, payload, JWT_MINUTES)

print("\nSTEP 4 - CREATE THE JWT TOKEN")
print("Token (first 60 chars):", token[:60], "...")
print(f"Claims: issuer={USER_NAME}, audience={RECEIVER_NAME}, expires in {JWT_MINUTES} minutes,")
print("        unique id (jti) and the fingerprint of the payload.")

# ------------------------------------------------------------------
# STEP 5 - SAVE JSON / PAYLOAD / SIGNATURE / TOKEN
#   record.json    = the original data (stays with me, I do NOT send it)
#   payload.json   = the encrypted package (goes to the receiver)
#   signature.txt  = the result of step 3 (goes to the receiver)
#   token.jwt      = the result of step 4 (goes to the receiver)
# ------------------------------------------------------------------
os.makedirs(DATA_DIR, exist_ok=True)
with open(os.path.join(DATA_DIR, "record.json"), "w") as f:
    json.dump(record, f, indent=4)
with open(os.path.join(DATA_DIR, "payload.json"), "w") as f:
    json.dump(payload, f, indent=4)
with open(os.path.join(DATA_DIR, "signature.txt"), "w") as f:
    f.write(signature)
with open(os.path.join(DATA_DIR, "token.jwt"), "w") as f:
    f.write(token)

print("\nSTEP 5 - SAVE JSON / PAYLOAD / SIGNATURE / TOKEN")
print("record.json   (original data, stays here)")
print("payload.json  (encrypted package)")
print("signature.txt (digital signature)")
print("token.jwt     (JWT token)")
print("Saved in:", DATA_DIR)

# ------------------------------------------------------------------
# SEND THE FILES
# The receiver is in ANOTHER container, so I send the files over the network.
# ------------------------------------------------------------------
print("\nSEND THE FILES")
print(f"POST {RECEIVER_URL}/receive")

answer = requests.post(
    f"{RECEIVER_URL}/receive",
    json={"payload": payload, "signature": signature, "token": token},
    timeout=20,
)

title("ANSWER OF THE RECEIVER")
result = answer.json()
print("Authorized sender (role professor):", "YES" if result["authorized"] else "NO")
print("Signature:", result["signature_label"])
print("JWT token:", result["jwt_label"])
print("FINAL    :", "VALID" if result["valid"] else "INVALID")
if result.get("reason"):
    print("Reason   :", result["reason"])
print("\nSENDER FINISHED")
