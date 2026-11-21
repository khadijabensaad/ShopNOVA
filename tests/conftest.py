"""Configuration des tests. Base SecOps isolée (fichier temporaire) ; le shim FastAPI n'est utilisé que si la
vraie bibliothèque est absente."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
os.environ["SECOPS_DB"] = str(Path(tempfile.mkdtemp()) / "secops-test.db")
os.environ.setdefault("SHOPNOVA_KEYS_DIR", tempfile.mkdtemp(prefix="shopnova-keys-"))  # jamais data/keys en test
os.environ["PLATFORM_PASSWORD"] = "ShopNova!2026"  # prioritaire sur .env (config utilise setdefault)
try:
    import fastapi  # noqa: F401
except ImportError:
    sys.path.insert(0, str(ROOT / "tests" / "shim"))
for sub in ("app", "agent", "data", "rag"):
    sys.path.insert(0, str(ROOT / sub))

if not (ROOT / ".env").exists():
    subprocess.run([sys.executable, str(ROOT / "setup_flags.py")], check=True)
if not (ROOT / "data" / "shop.db").exists():
    subprocess.run([sys.executable, str(ROOT / "data" / "seed.py")], check=True)

from starlette.testclient import TestClient  # noqa: E402

import server  # noqa: E402
from secops import db  # noqa: E402

PW = "ShopNova!2026"
H = {"X-Requested-With": "shopnova"}


@pytest.fixture()
def fresh():
    db.wipe_activity()
    yield


def client_as(user: str) -> TestClient:
    c = TestClient(server.app)
    r = c.post("/api/secops/auth/login", json={"username": user, "password": PW})
    assert r.status_code == 200, r.text
    return c


@pytest.fixture()
def as_user():
    return client_as
