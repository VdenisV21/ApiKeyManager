import os

DATA_FILE = os.getenv("APIKEYMGR_DATA_FILE", "data/api_keys.json")

SERVER_HOST = os.getenv("APIKEYMGR_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("APIKEYMGR_PORT", "8000"))

MAX_RETRIES = int(os.getenv("APIKEYMGR_MAX_RETRIES", "3"))
REQUEST_TIMEOUT = int(os.getenv("APIKEYMGR_REQUEST_TIMEOUT", "120"))
STREAMING_TIMEOUT = int(os.getenv("APIKEYMGR_STREAMING_TIMEOUT", "600"))

ADMIN_TOKEN_HEADER = "X-Admin-Token"
TARGET_SERVICE_HEADER = "X-Target-Service"
TARGET_MODEL_HEADER = "X-Target-Model"

APIKEY_PLACEHOLDER = "<apikey>"
