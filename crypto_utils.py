"""
crypto_utils.py  -  THE CRYPTOGRAPHY LIBRARY OF MY PROJECT

All the cryptography functions are here, in one place.
The other files (sender, receiver, attacker, ca_server) only CALL these functions.
This file does not run by itself, it is only a library.

Tools used (from the python "cryptography" package, and PyJWT for the token):
  - RSA 2048   : the key pair of every user (private key + public key)
  - AES-256-GCM: encrypts the data (fast, and it also detects changes)
  - RSA-OAEP   : encrypts the small AES key with the receiver's public key
  - RSA-PSS    : the digital signature (SHA-256)
  - X.509      : the certificate (the "ID card" of a user, signed by the CA)
  - JWT (RS256): a short-lived signed token (who sent it, for whom, until when)
  - JWT (RS256): a signed token with claims (who sent it, for whom, until when,
                 and the SHA-256 hash of the data)
"""

import os
import json
import uuid
import base64
import hashlib
import hashlib
from datetime import datetime, timedelta, timezone

import jwt  # PyJWT: library to create and check JWT tokens

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

import jwt  # PyJWT: the library for JSON Web Tokens


# ---------------------------------------------------------------
# Small helpers: files can only contain text, so I convert the
# raw bytes to base64 text (and back) when I save them in JSON.
# ---------------------------------------------------------------
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


# ===============================================================
# PART 1 - KEY PAIRS  (every user has HIS OWN private + public key)
# ===============================================================
def generate_key_pair():
    """Create a new RSA key pair. The private key object contains both keys."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save_private_key(private_key, path, password=None):
    """
    Save the PRIVATE key in a file. This one must stay secret!
    - If I give a password, the file is encrypted with the password.
    - chmod 600 = only the owner of the file can read it.
    """
    if password:
        protection = serialization.BestAvailableEncryption(password.encode())
    else:
        protection = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=protection,
    )
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem)
    os.chmod(path, 0o600)


def load_private_key(path, password=None):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=password.encode() if password else None
        )


def public_key_to_pem(public_key) -> bytes:
    """Turn a public key into PEM text. This one is public, I can share it."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)


# ===============================================================
# PART 2 - CERTIFICATES  (the CA says: "this public key is really Ali's")
# ===============================================================
def create_ca(ca_dir):
    """
    Create the Certificate Authority (CA): its own key pair and a
    self-signed certificate. The CA private key is used ONLY to sign
    the certificates of the users. It never leaves the CA server.
    """
    ca_key = generate_key_pair()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Secure Academic Records CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Academic Records"),
    ])
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed: issuer = subject
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    save_private_key(ca_key, os.path.join(ca_dir, "ca_private_key.pem"))
    with open(os.path.join(ca_dir, "ca_certificate.pem"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))


def load_certificate(pem: bytes):
    return x509.load_pem_x509_certificate(pem)


def issue_certificate(ca_key, ca_cert, username, user_public_key, role="pending") -> bytes:
    """
    The CA creates a certificate for a user:
    username + ROLE + user's PUBLIC key + signature of the CA.
    The role is written in the field OU (organizational unit). Because the CA signs the
    whole certificate, nobody can change the role without breaking the CA signature.
    Roles:  pending (new user, waiting for the admin) - professor (approved) - rejected - organization (the receiver)
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Academic Records"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())  # <- the CA signs with ITS private key
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def get_certificate_role(cert_pem: bytes) -> str:
    """Read the ROLE that the CA wrote inside a certificate (no role = pending)."""
    cert = load_certificate(cert_pem)
    values = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    return values[0].value if values else "pending"


def verify_certificate(cert_pem: bytes, ca_cert_pem: bytes, expected_username: str):
    """
    Check a certificate. Returns (True/False, reason).
    I check 4 things:
      1. the name inside is the user I expect
      2. it was issued by MY trusted CA
      3. the CA signature is real (nobody changed the certificate)
      4. it is not expired
    """
    try:
        cert = load_certificate(cert_pem)
        ca_cert = load_certificate(ca_cert_pem)

        name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if name != expected_username:
            return False, f"certificate is for '{name}', not for '{expected_username}'"

        if cert.issuer != ca_cert.subject:
            return False, "certificate was not issued by my trusted CA"

        # the CA public key checks the CA signature on the certificate
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return False, "certificate is expired or not valid yet"

        return True, "certificate is valid"
    except Exception as error:
        return False, f"certificate check failed ({error})"


# ===============================================================
# PART 3 - AES  (encrypt the data itself)
# ===============================================================
def generate_aes_key() -> bytes:
    """A new random 256-bit key. A new one for every message."""
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(data: str, aes_key: bytes):
    """
    Encrypt the data with AES-256-GCM.
    The nonce is a random number used only once for this encryption.
    GCM also adds an authentication tag: if somebody changes even
    one bit of the encrypted data, the decryption will fail.
    """
    nonce = os.urandom(12)
    encrypted = AESGCM(aes_key).encrypt(nonce, data.encode("utf-8"), None)
    return nonce, encrypted


def aes_decrypt(nonce: bytes, encrypted: bytes, aes_key: bytes) -> str:
    return AESGCM(aes_key).decrypt(nonce, encrypted, None).decode("utf-8")


# ===============================================================
# PART 4 - RSA ENCRYPTION OF THE AES KEY
# AES is fast but both sides need the same key. RSA solves this:
# I lock the AES key with the RECEIVER'S PUBLIC key, and only the
# receiver's PRIVATE key can open it. (This is called "hybrid encryption")
# ===============================================================
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def wrap_aes_key(aes_key: bytes, receiver_public_key) -> bytes:
    return receiver_public_key.encrypt(aes_key, _OAEP)


def unwrap_aes_key(wrapped_key: bytes, receiver_private_key) -> bytes:
    return receiver_private_key.decrypt(wrapped_key, _OAEP)


# ===============================================================
# PART 5 - DIGITAL SIGNATURE
# Sign   = SENDER'S PRIVATE key (only the sender can do it)
# Verify = SENDER'S PUBLIC key  (everybody can check it)
# The result of signing is the content of signature.txt
# ===============================================================
_PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def sign_data(data: str, private_key) -> str:
    """Sign the data with the private key -> signature (as base64 text)."""
    signature = private_key.sign(data.encode("utf-8"), _PSS, hashes.SHA256())
    return b64e(signature)


def verify_signature(data: str, signature_b64: str, public_key) -> bool:
    """True = data is authentic and not changed. False = something is wrong."""
    try:
        public_key.verify(b64d(signature_b64.strip()), data.encode("utf-8"), _PSS, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


# ===============================================================
# PART 6 - JWT TOKEN  (JSON Web Token)
# A JWT is a small signed "ticket". It has 3 parts: header.claims.signature
# The sender signs it with his PRIVATE key (RS256), the receiver checks it
# with the sender's PUBLIC key. The digital signature (part 5) protects the
# CONTENT of the data. The JWT protects WHO / FOR WHOM / UNTIL WHEN / ONCE:
#   iss          = issuer, who created the token (the sender)
#   aud          = audience, for whom it is (the receiver)
#   iat / exp    = created at / expires at  (short life)
#   jti          = a unique id, used ONE time only (against replay attacks)
#   payload_hash = fingerprint (SHA-256) of payload.json, so the token
#                  belongs to THIS package and not to another one
# ===============================================================
def payload_fingerprint(payload: dict) -> str:
    """SHA-256 fingerprint of the payload. Same payload = same fingerprint."""
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def create_jwt(private_key, issuer, audience, payload: dict, minutes=60) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
        "jti": str(uuid.uuid4()),
        "payload_hash": payload_fingerprint(payload),
    }
    return jwt.encode(claims, private_key, algorithm="RS256")


def verify_jwt(token: str, public_key, issuer, audience, check_exp=True) -> dict:
    """
    Check the token. It raises an error if:
    the signature is wrong, the issuer or audience is wrong, or it is expired.
    On success it returns the claims (the content of the token).
    """
    return jwt.decode(
        token.strip(), public_key, algorithms=["RS256"],
        issuer=issuer, audience=audience, leeway=10,
        options={"verify_exp": check_exp},
    )
