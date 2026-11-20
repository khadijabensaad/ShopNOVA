"""Lance le serveur pour les tests d'interface. Utilise la vraie bibliothèque FastAPI si elle est installée,
sinon le shim de test (tests/shim) — environnement hors-ligne uniquement.

Usage : python tests/run_dev_server.py [port]
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    import fastapi  # noqa: F401
except ImportError:
    sys.path.insert(0, str(ROOT / "tests" / "shim"))
sys.path.insert(0, str(ROOT / "app"))

import uvicorn  # noqa: E402

import server  # noqa: E402

uvicorn.run(server.app, host="127.0.0.1", port=int(sys.argv[1]) if len(sys.argv) > 1 else 8000, log_level="warning")
