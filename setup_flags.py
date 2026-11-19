"""Crée .env avec des flags aléatoires. Usage : python setup_flags.py  (--force pour régénérer)"""
import secrets
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
env = root / ".env"
if env.exists() and "--force" not in sys.argv:
    sys.exit(".env existe déjà (utiliser --force pour régénérer les flags).")
lines = []
for line in (root / ".env.example").read_text(encoding="utf-8").splitlines():
    if line.startswith("FLAG_") and line.endswith("="):
        name = line[:-1]
        line = f"{name}=FLAG{{{name[5:].lower()}_{secrets.token_hex(3)}}}"
    lines.append(line)
env.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(".env créé avec des flags aléatoires.")
