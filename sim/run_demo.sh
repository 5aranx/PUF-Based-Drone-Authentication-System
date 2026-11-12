#!/usr/bin/env bash
# Full demo script: start backend, enroll two drones, run auth scenarios
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/../backend"
SERVER="http://127.0.0.1:5000"

export NO_PROXY=localhost,127.0.0.1
export no_proxy=localhost,127.0.0.1

echo "=== PUF Drone Authentication Demo ==="
echo ""

# 1. Start the backend in background
echo "[1/5] Starting Flask backend..."
cd "$BACKEND_DIR"
rm -f puf_drone.db
source .venv/bin/activate
export FLASK_APP=app.py
export FLASK_DEBUG=0
python3 app.py &
FLASK_PID=$!
sleep 2
echo "      Backend PID: $FLASK_PID"

# 2. Enroll DRONE-001
echo ""
echo "[2/5] Enrolling DRONE-001 (legitimate chip: CHIP-ALPHA-001)..."
cd "$SCRIPT_DIR"
source .venv/bin/activate
python3 sim_enrollment.py --chip-id CHIP-ALPHA-001 --device-id DRONE-001 --server "$SERVER"

# 3. Enroll DRONE-002
echo ""
echo "[3/5] Enrolling DRONE-002 (legitimate chip: CHIP-BETA-002)..."
python3 sim_enrollment.py --chip-id CHIP-BETA-002 --device-id DRONE-002 --server "$SERVER"

# 4. Auth scenarios
echo ""
echo "[4/5] Running authentication scenarios..."
python3 sim_auth.py \
    --chip-id CHIP-ALPHA-001 \
    --device-id DRONE-001 \
    --server "$SERVER" \
    --impostor-chip-id CHIP-IMPOSTOR-999 \
    --replay

# 5. Cleanup
echo ""
echo "[5/5] Demo complete. Stopping backend (PID $FLASK_PID)..."
kill "$FLASK_PID" 2>/dev/null || true
echo "Dashboard was running at: http://127.0.0.1:5000/dashboard"
