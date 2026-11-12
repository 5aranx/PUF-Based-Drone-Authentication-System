import os

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod-32bytes-long!")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 900          # 15 min
NONCE_TTL_SECONDS = 60
MAX_TS_SKEW_SECONDS = 30
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION_SECONDS = 30
DATABASE_PATH = os.environ.get("DB_PATH", "puf_drone.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "admin-secret")
