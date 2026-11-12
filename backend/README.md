# Ground Control Station (GCS) Backend

Flask server providing authentication endpoints, session issuance, rate limiting, and an interactive real-time command dashboard.

## Features

- **Device Registry:** Stores public helper data $H$, dark-bit masks, and verification key commitments in SQLite.
- **Challenge-Response Auth:**
  - `GET /challenge?device_id=...`: Issues cryptographically random single-use nonces with 60s TTL.
  - `POST /verify`: Performs constant-time `hmac.compare_digest` verification and consumes nonces atomically.
  - Brute-force mitigation: Automatic lockout after 5 consecutive failures.
- **Session Tokens:** Issues JWT session tokens derived via `HKDF-SHA256(K, Nonce)`.
- **Telemetry Ingestion:** Validates incoming drone telemetry using active session tokens.
- **Tactical Dashboard:** Real-time Server-Sent Events (SSE) feed, attitude horizon indicator, and live security event logs.

## Running the Server

```bash
cd /home/savi/Projects/puf-drone/backend
source .venv/bin/activate
python3 app.py
```

Dashboard is served at: `http://localhost:5000/dashboard`
