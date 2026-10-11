# IDS Experiment 14 — Challenge–Response Authentication (JavaScript)

**Student:** JANARDHAN VEMA  
**Roll No.:** 2024UCS1538

## Features
- Browser-side PBKDF2-HMAC-SHA256, 200,000 iterations, 16-byte random salt.
- Raw password is never sent to the server.
- Server issues a random 32-byte challenge with a 60-second expiry.
- Server signs the canonical challenge payload using RSA-2048 / RSA-PSS / SHA-256.
- Browser verifies the server signature using the Web Crypto API.
- Browser sends HMAC-SHA256(verifier, challenge); server compares in constant time.
- Challenge is consumed on first verification attempt; replay control demonstrates rejection.
- Random session token is returned after successful authentication.
- JSON user store and audit log for classroom use.

## Requirements and run
Node.js 18+ and npm. In this folder:
1. `npm install`
2. `npm start`
3. Open `http://localhost:3000`
4. Register a username/password (minimum 8 characters).
5. Log in with those credentials.
6. Click **Replay last response**; the server should return `Challenge already used — REPLAY ATTACK BLOCKED.`
7. Try a wrong password; login should fail with an HMAC mismatch.
8. Click **Refresh log** to view audit events.

## Endpoints
- `GET /api/status`
- `GET /api/public-key`
- `POST /api/register`
- `POST /api/request-challenge`
- `POST /api/verify`
- `GET /api/audit` (local demo only)

## Files
`server.js`, `package.json`, `public/index.html`, `public/style.css`, `public/app.js`; `data/users.json` and `data/audit.log` are created at runtime.

## Security limitations
This is a teaching prototype, not production-ready. RSA keys are regenerated on restart; challenge/session data is in memory; user records use a JSON file; there is no HTTPS. The stored PBKDF2 verifier is itself sensitive and its theft could enable impersonation in this simplified protocol. Production requires HTTPS, persistent atomic nonce storage, rate limiting, secure session-cookie handling, managed keys, and a protocol review (consider a PAKE). Do not expose this demo to the public internet.
