import sqlite3
import time
from contextlib import contextmanager

# Default, can be overridden at module level for testing
DATABASE_PATH = "puf_drone.db"


def _load_db_path():
    """Read DATABASE_PATH from config (allows override via os.environ before import)."""
    try:
        from config import DATABASE_PATH as _p
        return _p
    except ImportError:
        return DATABASE_PATH


@contextmanager
def _get_conn():
    path = DATABASE_PATH  # module-level, allows test overrides
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id   TEXT PRIMARY KEY,
                mask        TEXT NOT NULL,
                helper      TEXT NOT NULL,
                k_commit    TEXT NOT NULL,
                k_hex       TEXT NOT NULL,
                enrolled_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS nonces (
                nonce      TEXT PRIMARY KEY,
                device_id  TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS auth_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                event     TEXT NOT NULL,
                detail    TEXT
            );
        """)


def register_device(device_id: str, mask_hex: str, helper_hex: str,
                    k_commit_hex: str, k_hex: str) -> bool:
    """Return True on success, False if device_id already exists."""
    try:
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO devices (device_id, mask, helper, k_commit, k_hex, enrolled_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (device_id, mask_hex, helper_hex, k_commit_hex, k_hex, int(time.time()))
            )
        return True
    except sqlite3.IntegrityError:
        return False


def get_device(device_id: str):
    """Return device row as dict, or None."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
    return dict(row) if row else None


def store_nonce(nonce: str, device_id: str, expires_at: int):
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO nonces (nonce, device_id, expires_at, used) VALUES (?, ?, ?, 0)",
            (nonce, device_id, expires_at)
        )


def consume_nonce(nonce: str, device_id: str) -> bool:
    """
    Atomically validate and burn the nonce.
    Returns True only if nonce exists, belongs to device_id, is unused, and not expired.
    Always marks used=1, even on failure (defensive).
    """
    now = int(time.time())
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT device_id, expires_at, used FROM nonces WHERE nonce = ?", (nonce,)
        ).fetchone()

        if row is None:
            return False

        # Always burn it
        conn.execute("UPDATE nonces SET used = 1 WHERE nonce = ?", (nonce,))

        if row["used"] == 1:
            return False
        if row["device_id"] != device_id:
            return False
        if row["expires_at"] < now:
            return False

    return True


def log_event(device_id: str, event: str, detail: str = None):
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO auth_log (ts, device_id, event, detail) VALUES (?, ?, ?, ?)",
            (int(time.time()), device_id, event, detail)
        )


def get_recent_log(limit: int = 50):
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM auth_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_all_devices():
    """Return all devices with their most-recent auth event appended."""
    with _get_conn() as conn:
        devices = conn.execute("SELECT * FROM devices ORDER BY enrolled_at DESC").fetchall()
        result = []
        for d in devices:
            d_dict = dict(d)
            last = conn.execute(
                "SELECT ts, event, detail FROM auth_log WHERE device_id = ? ORDER BY id DESC LIMIT 1",
                (d["device_id"],)
            ).fetchone()
            d_dict["last_event"] = dict(last) if last else None
            result.append(d_dict)
    return result


def get_failure_count(device_id: str, since_ts: int) -> int:
    """Count REJECT/LOCKED/NONCE_REUSED/PUF_MISMATCH events since `since_ts`."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM auth_log "
            "WHERE device_id = ? AND ts >= ? AND event IN ('REJECT','LOCKED','NONCE_REUSED','PUF_MISMATCH')",
            (device_id, since_ts)
        ).fetchone()
    return row["cnt"] if row else 0


def get_last_auth(device_id: str):
    """Return the most recent auth_log entry for this device, or None."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM auth_log WHERE device_id = ? ORDER BY id DESC LIMIT 1",
            (device_id,)
        ).fetchone()
    return dict(row) if row else None
