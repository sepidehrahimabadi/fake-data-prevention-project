"""
registration.py  -  REGISTER A USER AND GET PUBLIC KEYS FROM THE CA

Used by the sender, the receiver and the attacker.

How registration works (like making an ID card):
  1. The user creates HIS OWN key pair on HIS OWN computer.
  2. The private key stays there, in his keys folder. It is never sent.
  3. Only the PUBLIC key is sent to the CA.
  4. The CA creates a certificate (name + ROLE + public key + CA signature)
     and keeps it in its public directory.
  5. A normal user gets the role "pending". Only the ADMIN can approve him as
     "professor". The receiving organization has a reserved name and a secret.
"""

import os
import time
import requests

from crypto_utils import (
    generate_key_pair, save_private_key, load_private_key,
    public_key_to_pem, verify_certificate, load_certificate, get_certificate_role,
)


def wait_for_ca(ca_url, tries=30):
    """The CA container may start a few seconds later, so I try again and again."""
    for _ in range(tries):
        try:
            if requests.get(f"{ca_url}/health", timeout=2).ok:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise RuntimeError("The CA server is not reachable.")


def register_user(username, keys_dir, ca_url, password=None, registration_secret=None, identity=None):
    """
    Create the key pair (only the first time), register the public key at the
    CA and save the certificate. Returns the PRIVATE key of the user.
    registration_secret is only used by the receiving organization.
    identity = {"full_name": ..., "staff_id": ...} is given only at the first registration,
    so that the admin can compare it with the university records.
    """
    user_dir = os.path.join(keys_dir, username)
    private_path = os.path.join(user_dir, "private_key.pem")

    if os.path.exists(private_path):
        # the user is already registered: I do NOT create new keys
        private_key = load_private_key(private_path, password)
        print(f"[register] '{username}' already has keys, I load them.")
    else:
        private_key = generate_key_pair()
        save_private_key(private_key, private_path, password)
        with open(os.path.join(user_dir, "public_key.pem"), "wb") as f:
            f.write(public_key_to_pem(private_key.public_key()))
        print(f"[register] New key pair created for '{username}'.")
        print(f"[register] PRIVATE key stays secret in: {private_path}")

    # send ONLY the public key to the CA
    wait_for_ca(ca_url)
    body = {"username": username, "public_key": public_key_to_pem(private_key.public_key()).decode()}
    if registration_secret:
        body["registration_secret"] = registration_secret
    if identity:
        body.update({k: v for k, v in identity.items() if v})
    answer = requests.post(f"{ca_url}/register", json=body, timeout=10)
    if not answer.ok:
        raise RuntimeError(f"CA refused the registration: {answer.json().get('error')}")

    certificate = answer.json()["certificate"]
    with open(os.path.join(user_dir, "certificate.pem"), "w") as f:
        f.write(certificate)
    print(f"[register] Certificate of '{username}' received from the CA "
          f"(role: {get_certificate_role(certificate.encode())}).")
    return private_key


def fetch_verified_certificate(ca_url, username, ca_cert_path):
    """
    Get the certificate of another user from the CA, but DON'T trust it blindly:
    first I check it with the CA certificate that I already have.
    Returns (public key, role). The ROLE comes from the certificate that the CA signed.
    """
    answer = requests.get(f"{ca_url}/certificate/{username}", timeout=10)
    if not answer.ok:
        raise RuntimeError(f"'{username}' is not registered at the CA.")

    with open(ca_cert_path, "rb") as f:
        ca_cert_pem = f.read()

    ok, reason = verify_certificate(answer.content, ca_cert_pem, username)
    if not ok:
        raise RuntimeError(f"Bad certificate of '{username}': {reason}")

    return load_certificate(answer.content).public_key(), get_certificate_role(answer.content)


def fetch_verified_public_key(ca_url, username, ca_cert_path, required_role=None):
    """
    Same as above, but returns only the public key.
    If required_role is given, the role in the certificate must be exactly this role
    (for example the sender only sends to the user with the role "organization").
    """
    public_key, role = fetch_verified_certificate(ca_url, username, ca_cert_path)
    if required_role and role != required_role:
        raise RuntimeError(
            f"'{username}' has the role '{role}', but the role '{required_role}' is required."
        )
    return public_key
