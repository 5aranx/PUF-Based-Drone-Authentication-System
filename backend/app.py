import json
import queue
import time
from collections import defaultdict, deque
from functools import wraps

from flask import Flask, Response, g, jsonify, redirect, render_template, request, stream_with_context
from flask_cors import CORS

from config import (
    ADMIN_TOKEN,
    LOCKOUT_DURATION_SECONDS,
    LOCKOUT_THRESHOLD,
    MAX_TS_SKEW_SECONDS,
    NONCE_TTL_SECONDS,
)
from models import (
    consume_nonce,
    get_all_devices,
    get_device,
    get_failure_count,
    get_recent_log,
    init_db,
    log_event,
    register_device,
    store_nonce,
)
from puf_crypto import (
    decode_jwt,
    derive_session_key,
    generate_nonce,
    issue_jwt,
    verify_hmac,
)

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------------------------
# In-memory telemetry store: device_id → deque(last 100 readings)
# ---------------------------------------------------------------------------
_telemetry: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

# ---------------------------------------------------------------------------
# SSE broadcaster — a list of per-client queues
# ---------------------------------------------------------------------------
_sse_clients: list[queue.Queue] = []


def _broadcast(event_dict: dict):
    """Push an event to all connected SSE clients."""
    payload = json.dumps(event_dict)
    dead = []
    for q in _sse_clients:
        try:
            q.put_nowait(payload)
        except queue.Full:
            dead.append(q)
    for q in dead:
        try:
            _sse_clients.remove(q)
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != ADMIN_TOKEN:
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return wrapper


def _require_jwt(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        token = auth[7:]
        try:
            payload = decode_jwt(token)
        except Exception as exc:
            return jsonify({"error": "Invalid token", "detail": str(exc)}), 401
        g.jwt_payload = payload
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# --- Enroll ---

@app.route("/enroll", methods=["POST"])
@_require_admin
def enroll():
    data = request.get_json(force=True) or {}
    required = ("device_id", "mask", "helper", "k_commit", "k_hex")
    missing = [k for k in required if k not in data]
    if missing:
        return jsonify({"error": "Missing fields", "fields": missing}), 400

    ok = register_device(
        data["device_id"],
        data["mask"],
        data["helper"],
        data["k_commit"],
        data["k_hex"],
    )
    if not ok:
        return jsonify({"error": "Device already enrolled"}), 409

    _broadcast({"type": "enroll", "device_id": data["device_id"], "ts": int(time.time())})
    return jsonify({"status": "enrolled", "device_id": data["device_id"]}), 201


# --- Challenge ---

@app.route("/challenge", methods=["GET"])
def challenge():
    device_id = request.args.get("device_id", "").strip()
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    device = get_device(device_id)
    if device is None:
        return jsonify({"error": "Device not found"}), 404

    now = int(time.time())
    fail_count = get_failure_count(device_id, now - LOCKOUT_DURATION_SECONDS)
    if fail_count >= LOCKOUT_THRESHOLD:
        return jsonify({"error": "LOCKED", "retry_after": LOCKOUT_DURATION_SECONDS}), 429

    nonce = generate_nonce()
    store_nonce(nonce, device_id, now + NONCE_TTL_SECONDS)
    return jsonify({"nonce": nonce})


# --- Verify ---

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(force=True) or {}
    required = ("device_id", "nonce", "ts", "mac")
    missing = [k for k in required if k not in data]
    if missing:
        return jsonify({"error": "Missing fields", "fields": missing}), 400

    device_id = data["device_id"]
    nonce_hex = data["nonce"]
    ts_str = str(data["ts"])
    mac_hex = data["mac"]

    # Timestamp skew check
    try:
        client_ts = int(ts_str)
    except ValueError:
        return jsonify({"error": "Invalid ts"}), 400

    now = int(time.time())
    if abs(now - client_ts) > MAX_TS_SKEW_SECONDS:
        log_event(device_id, "REJECT", f"ts_skew={now - client_ts}s")
        return jsonify({"error": "REJECT", "reason": "timestamp skew"}), 401

    # Nonce consumption (atomic)
    if not consume_nonce(nonce_hex, device_id):
        log_event(device_id, "NONCE_REUSED", nonce_hex[:16] + "…")
        _broadcast({"type": "auth", "device_id": device_id, "event": "NONCE_REUSED", "ts": now})
        return jsonify({"error": "NONCE_REUSED"}), 401

    # Device lookup
    device = get_device(device_id)
    if device is None:
        return jsonify({"error": "Device not found"}), 404

    # HMAC verification
    if not verify_hmac(device["k_hex"], device_id, nonce_hex, ts_str, mac_hex):
        fail_count = get_failure_count(device_id, now - LOCKOUT_DURATION_SECONDS) + 1
        if fail_count >= LOCKOUT_THRESHOLD:
            log_event(device_id, "LOCKED", f"failures={fail_count}")
            _broadcast({"type": "auth", "device_id": device_id, "event": "LOCKED", "ts": now})
            return jsonify({"error": "LOCKED", "retry_after": LOCKOUT_DURATION_SECONDS}), 401

        log_event(device_id, "REJECT", f"hmac_mismatch failures={fail_count}")
        _broadcast({"type": "auth", "device_id": device_id, "event": "REJECT", "ts": now})
        return jsonify({"error": "REJECT", "reason": "hmac_mismatch"}), 401

    # Success
    session_key = derive_session_key(device["k_hex"], nonce_hex)
    token = issue_jwt(device_id, session_key)
    log_event(device_id, "AUTH_OK")
    _broadcast({"type": "auth", "device_id": device_id, "event": "AUTH_OK", "ts": now})
    return jsonify({"token": token, "session_key": session_key}), 200


# --- Telemetry ---

@app.route("/telemetry", methods=["POST"])
@_require_jwt
def telemetry():
    data = request.get_json(force=True) or {}
    device_id = g.jwt_payload.get("sub")
    reading = {
        "device_id": device_id,
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "alt": data.get("alt"),
        "heading": data.get("heading"),
        "ts": data.get("ts", int(time.time())),
    }
    _telemetry[device_id].append(reading)
    _broadcast({"type": "telemetry", **reading})
    return jsonify({"status": "ok"}), 200


# --- Fleet & Log APIs ---

@app.route("/api/device/<device_id>")
def api_device(device_id):
    device = get_device(device_id)
    if device is None:
        return jsonify({"error": "Device not found"}), 404
    return jsonify({
        "device_id": device["device_id"],
        "mask": device["mask"],
        "helper": device["helper"],
        "k_commit": device["k_commit"],
        "enrolled_at": device["enrolled_at"],
    })


@app.route("/api/fleet")
def api_fleet():
    return jsonify(get_all_devices())


@app.route("/api/log")
def api_log():
    return jsonify(get_recent_log(50))


@app.route("/api/telemetry/<device_id>")
def api_telemetry(device_id):
    readings = list(_telemetry.get(device_id, []))
    return jsonify(readings)


# --- SSE ---

@app.route("/events")
def events():
    client_q: queue.Queue = queue.Queue(maxsize=200)
    _sse_clients.append(client_q)

    def generate():
        # Send a heartbeat immediately so the browser knows we're alive
        yield "data: {\"type\":\"heartbeat\"}\n\n"
        try:
            while True:
                try:
                    payload = client_q.get(timeout=20)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    # Keep-alive comment
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            pass
        finally:
            try:
                _sse_clients.remove(client_q)
            except ValueError:
                pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
