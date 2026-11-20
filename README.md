# SEC-PRJ-7E_25 - Fake Data Prevention with Conventional Cryptotools

Digital signatures + certificates + AES encryption + JWT (+ a MongoDB database).

Two independent users (sender and receiver), a Certificate Authority, and an attacker.
Everything runs in separate Docker containers. Each user has HIS OWN key pair.

## Configuration

Before starting the project, create a `.env` file in the project root with these variables:

```env
ORGANIZATION_SECRET=your-organization-secret
ADMIN_USER=admin
ADMIN_PASSWORD=your-admin-password

SENDER_KEY_PASSWORD=your-sender-password
RECEIVER_KEY_PASSWORD=your-receiver-password
ATTACKER_KEY_PASSWORD=your-attacker-password
```

Use your own values. Never upload the `.env` file to GitHub.

## Run it (copy and paste)

```bash
# 1. Start the CA and the receiver (User 2, independent server)
docker compose up -d --build ca mongo receiver

# 2. User 1 (a NEW user) runs the sender
docker compose run --rm --build sender

# 2b. The ADMIN approves him:
# Open http://localhost:5001/admin
# Log in using ADMIN_USER and ADMIN_PASSWORD from your .env file.
# Click "Approve as professor" (or "Reject").

# 2c. Run the sender again
docker compose run --rm sender

# 3. Run the attacker
docker compose run --rm --build attacker

# See what the receiver printed
docker compose logs receiver

# Look inside the MongoDB database
docker compose exec mongo mongosh secure_certificate --eval "db.log.find().pretty()"
```

## Roles and the admin

- Everybody who registers gets the status **pending** (the role is written by the CA inside his certificate and signed).
- Only the **admin** (page `http://localhost:5001/admin`) can **approve** a professor or **reject** a user. Use the credentials defined in your local `.env` file.
- At registration the user gives his **full name** and a **university staff ID**. The admin page shows them, and the admin compares them with the university records. A staff ID can be used by only one user. (A staff ID is used, not the codice fiscale, which is personal data.)
- A pending or rejected user is told to wait or told no. The sender program does not even try to send.
- The **receiver** is the unique receiving organization: its name is reserved at the CA and can only be registered with a secret.
- The receiver accepts only a **professor**, even if somebody sends directly without the sender program (see attack 4). The sender sends only to the certified organization.

## Or use the web pages (buttons, like the professor described)

1. Open **http://localhost:5002** (User 1, sender): type a user name, a full name and a **university staff ID** (for example `PROF-2041`), click **Register** (his own key pair is made), then fill the record and click **Encrypt, sign and send**.
2. A new user is pending: the page says to wait. Open **http://localhost:5001/admin**, log in using your local `.env` credentials, approve him as professor, then click Send again.
3. Open **http://localhost:5003** (User 2, receiver) in another tab: see the history, or pick the files and the public key by hand.
4. MongoDB Compass: `mongodb://localhost:27018` (database `secure_certificate`).

## Another user, with other keys

```bash
docker compose run --rm -e USER_NAME=ali -e FULL_NAME="Ali Rossi" -e STAFF_ID=PROF-2042 sender
```

## Verify by hand (another browser tab, like the professor asked)

1. Open http://localhost:5003
2. Pick `sender_data/payload.json`, `sender_data/signature.txt`,
   `sender_data/token.jwt` and the sender's `public_key.pem` -> **VALID**
3. Try again with `attacker_keys/attacker/public_key.pem` -> **INVALID**

## Start from zero

```bash
./reset.sh
```

## Without Docker (only for testing)

Run `ca_server.py`, `receiver.py`, `sender.py` in 3 terminals, with

```bash
CA_URL=http://localhost:5001 RECEIVER_URL=http://localhost:5003
CA_DIR=./ca_data TRUST_DIR=./trust KEYS_DIR=./sender_keys DATA_DIR=./sender_data
```

(Set the right `KEYS_DIR` / `DATA_DIR` for each program.)

## Files

| File | What it is |
|---|---|
| `crypto_utils.py` | the cryptography library (RSA, AES, signature, certificates, JWT) |
| `registration.py` | make my key pair, register at the CA, get other public keys |
| `ca_server.py` | Certificate Authority, public directory, roles and the admin page |
| `sender.py` | User 1 in the terminal: register, produce, encrypt, sign, JWT, save, send |
| `sender_web.py` | User 1 with a web page (Register and Send buttons), same steps |
| `receiver.py` | User 2: load, decrypt, verify signature, check JWT (+ web page + MongoDB database) |
| `attacker.py` | tampering, impersonation, replay, unapproved user and fake receiver attacks |
| `examples/` | a sample record and the expected output of a good run |
| `STUDY_GUIDE.md` | how to explain the whole project |
