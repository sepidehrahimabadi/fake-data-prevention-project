"""
attacker.py  -  THE ATTACKER (to show that the system really protects the data)

The attacker is a THIRD person. He can see what travels on the network
(payload.json, signature.txt, the public keys). He does NOT have the
private key of the sender.

Attack 1 - TAMPERING:      change the grade 28 -> 30 but keep the old signature.
Attack 2 - IMPERSONATION:  pretend to be the sender and sign with his own key.
Attack 3 - REPLAY:         send the SAME good files again (the JWT stops it).
Attack 4 - UNAPPROVED:     register normally (pending) and send his own grade directly (the ROLE stops it).
Attack 5 - FAKE RECEIVER:  try to become the receiving organization (the CA stops it).

All five attacks must end with:  INVALID (or REFUSED).

Run it with:   docker compose run --rm attacker
"""

import os
import json
import requests

from crypto_utils import generate_aes_key, aes_encrypt, wrap_aes_key, sign_data, create_jwt, b64e, public_key_to_pem
from registration import register_user, fetch_verified_public_key

KEYS_DIR = os.environ.get("KEYS_DIR", "/app/keys")
CAPTURED_DIR = os.environ.get("CAPTURED_DIR", "/app/captured")  # files seen on the "network"
CA_URL = os.environ.get("CA_URL", "http://ca:5001")
RECEIVER_URL = os.environ.get("RECEIVER_URL", "http://receiver:5003")
CA_CERT_PATH = os.path.join(os.environ.get("TRUST_DIR", "/app/trust"), "ca_certificate.pem")
KEY_PASSWORD = os.environ.get("KEY_PASSWORD")

print("=" * 60)
print("ATTACKER")
print("=" * 60)

# the attacker captured the files of the sender from the network
with open(os.path.join(CAPTURED_DIR, "signature.txt")) as f:
    old_signature = f.read()
with open(os.path.join(CAPTURED_DIR, "token.jwt")) as f:
    old_token = f.read()
with open(os.path.join(CAPTURED_DIR, "payload.json")) as f:
    captured_payload = json.load(f)

# The attacker can encrypt for the receiver, because the receiver's
# public key is PUBLIC. But encrypting is not the same as signing!
receiver_public_key = fetch_verified_public_key(CA_URL, captured_payload["receiver"], CA_CERT_PATH)


def make_payload(sender_name, fake_data):
    """Encrypt a fake record for the receiver (same format as the sender)."""
    aes_key = generate_aes_key()
    nonce, encrypted = aes_encrypt(fake_data, aes_key)
    return {
        "sender": sender_name,
        "receiver": captured_payload["receiver"],
        "nonce": b64e(nonce),
        "encrypted_data": b64e(encrypted),
        "encrypted_key": b64e(wrap_aes_key(aes_key, receiver_public_key)),
    }


fake_record = {"student_id": "STU-1024", "course": "Data Security", "grade": 30, "semester": "2026"}
fake_data = json.dumps(fake_record, sort_keys=True)


def send(name, payload, signature, token):
    answer = requests.post(f"{RECEIVER_URL}/receive", json={"payload": payload, "signature": signature, "token": token}, timeout=20)
    result = answer.json()
    print(f"\nResult of {name}:", "VALID  <-- the attack worked!?" if result["valid"] else "INVALID  <-- the attack failed")
    print("Reason:", result.get("reason"))


# ---------------- ATTACK 1: TAMPERING ----------------
print("\nATTACK 1 - TAMPERING: grade 28 -> 30, with the OLD signature")
send("attack 1", make_payload(captured_payload["sender"], fake_data), old_signature, old_token)

# ---------------- ATTACK 2: IMPERSONATION ----------------
print(f"\nATTACK 2 - IMPERSONATION: I say I am '{captured_payload['sender']}' but I sign with MY key")
my_private_key = register_user("attacker", KEYS_DIR, CA_URL, KEY_PASSWORD,
                               identity={"full_name": "Mallory Attacker", "staff_id": "PROF-9999"})  # the attacker has his own valid keys
fake_signature = sign_data(fake_data, my_private_key)
fake_payload = make_payload(captured_payload["sender"], fake_data)
fake_token = create_jwt(my_private_key, captured_payload["sender"], captured_payload["receiver"], fake_payload)
send("attack 2", fake_payload, fake_signature, fake_token)

# ---------------- ATTACK 3: REPLAY ----------------
print("\nATTACK 3 - REPLAY: I send the SAME good files again (nothing changed)")
send("attack 3", captured_payload, old_signature, old_token)

# ---------------- ATTACK 4: A REGISTERED STUDENT SENDS HIS OWN GRADE ----------------
print("\nATTACK 4 - UNAPPROVED USER: I register normally (status: pending) and send my own grade directly,")
print("          without the sender program (my signature and my token are real!)")
unapproved_payload = make_payload("attacker", fake_data)
unapproved_signature = sign_data(fake_data, my_private_key)
unapproved_token = create_jwt(my_private_key, "attacker", captured_payload["receiver"], unapproved_payload)
send("attack 4", unapproved_payload, unapproved_signature, unapproved_token)

# ---------------- ATTACK 5: FAKE RECEIVER ----------------
receiver_name = captured_payload["receiver"]
print(f"\nATTACK 5 - FAKE RECEIVER: I try to become the receiving organization '{receiver_name}'")
answer = requests.post(f"{CA_URL}/register", json={
    "username": receiver_name, "public_key": public_key_to_pem(my_private_key.public_key()).decode()}, timeout=10)
if answer.ok:
    print("Result of attack 5a: ACCEPTED  <-- the attack worked!?")
else:
    print("Result of attack 5a: REFUSED by the CA  <-- the attack failed")
    print("Reason:", answer.json().get("error"))
try:
    fetch_verified_public_key(CA_URL, "attacker", CA_CERT_PATH, required_role="organization")
    print("Result of attack 5b: a sender would send to me  <-- the attack worked!?")
except RuntimeError as error:
    print("Result of attack 5b: a sender would REFUSE to send to me  <-- the attack failed")
    print("Reason:", error)

print("\nATTACKER FINISHED")
