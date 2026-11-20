"""Authentification, sessions et contrôle d'accès basé sur les rôles (RBAC) de la plateforme SecOps.

Tout est appliqué côté serveur : masquer un menu dans l'interface ne donne ni ne retire aucun droit.
- Mots de passe : PBKDF2-HMAC-SHA256 (200 000 itérations, sel aléatoire par compte).
- Sessions : jeton aléatoire en cookie HttpOnly + SameSite=Strict ; seule son empreinte SHA-256 est stockée.
- CSRF : toute requête qui modifie l'état doit porter l'en-tête X-Requested-With: shopnova (impossible à
  envoyer depuis un autre site sans pré-vérification CORS, que le serveur n'autorise pas).
- Limitation des tentatives de connexion : 5 échecs / 5 minutes par couple (identifiant, adresse IP).
"""
import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict

from . import db

COOKIE = "snv_session"
SESSION_TTL = 8 * 3600
ITERATIONS = 200_000
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "shopnova"

ROLES = {
    "admin": {"label": "Administrateur", "team": None},
    "agent_team": {"label": "AI Agent Attack Team", "team": "AGT"},
    "llm_team": {"label": "LLM Attack Team", "team": "LLM"},
    "rag_team": {"label": "RAG Attack Team", "team": "RAG"},
    "blue_team": {"label": "Blue Team / Defender", "team": "BLUE"},
    "auditor": {"label": "Auditeur", "team": None},
}

# Matrice des permissions. "workspace:X" = accès à l'espace de travail de l'équipe X.
PERMISSIONS = {
    "admin": {"*"},
    "agent_team": {"read", "workspace:AGT", "run:AGT", "retest:AGT", "edit:AGT", "evidence:AGT", "run:XC"},
    "llm_team": {"read", "workspace:LLM", "run:LLM", "retest:LLM", "edit:LLM", "evidence:LLM", "run:XC"},
    "rag_team": {"read", "workspace:RAG", "run:RAG", "retest:RAG", "edit:RAG", "evidence:RAG", "run:XC"},
    "blue_team": {"read", "workspace:BLUE", "triage", "evidence:*", "audit:read", "history:*", "report:export",
                  "monitoring"},
    "auditor": {"read", "evidence:*", "audit:read", "history:*", "report:export", "monitoring"},
}

DEMO_USERS = [
    ("admin", "Administrateur du lab", "admin"),
    ("agent", "Équipe AI Agent", "agent_team"),
    ("llm", "Équipe LLM", "llm_team"),
    ("rag", "Équipe RAG", "rag_team"),
    ("blue", "Blue Team", "blue_team"),
    ("auditor", "Auditeur", "auditor"),
]
DEFAULT_PASSWORD = "ShopNova!2026"

_failures: dict[tuple, list] = defaultdict(list)
MAX_FAILURES, WINDOW = 5, 300


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, it, salt, digest = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


def lab_password() -> str:
    return os.getenv("PLATFORM_PASSWORD") or DEFAULT_PASSWORD


def using_default_password() -> bool:
    return not os.getenv("PLATFORM_PASSWORD")


def ensure_demo_users() -> None:
    """Crée les comptes de démonstration au premier démarrage (mot de passe : PLATFORM_PASSWORD du .env)."""
    if db.q1("SELECT COUNT(*) AS n FROM users")["n"]:
        return
    pw = lab_password()
    for username, name, role in DEMO_USERS:
        db.insert("users", {"username": username, "display_name": name, "role": role,
                            "team": ROLES[role]["team"], "pw_hash": hash_password(pw), "active": 1,
                            "created_at": db.now()})


def public_user(u: dict) -> dict:
    perms = sorted(PERMISSIONS.get(u["role"], set()))
    return {"username": u["username"], "display_name": u["display_name"], "role": u["role"],
            "role_label": ROLES[u["role"]]["label"], "team": u["team"], "permissions": perms}


def _key(username: str, ip: str) -> tuple:
    return (username.lower(), ip or "-")


def login(username: str, password: str, ip: str) -> tuple[str, dict]:
    key = _key(username, ip)
    now = time.time()
    _failures[key] = [t for t in _failures[key] if now - t < WINDOW]
    if len(_failures[key]) >= MAX_FAILURES:
        raise AuthError(429, "Trop de tentatives. Réessayez dans quelques minutes.")
    u = db.q1("SELECT * FROM users WHERE username=? AND active=1", (username,))
    if not u or not verify_password(password, u["pw_hash"]):
        _failures[key].append(now)
        raise AuthError(401, "Identifiant ou mot de passe incorrect.")
    _failures.pop(key, None)
    token = secrets.token_urlsafe(32)
    db.insert("sessions", {"token_hash": hashlib.sha256(token.encode()).hexdigest(), "user_id": u["id"],
                           "created_at": now, "expires_at": now + SESSION_TTL})
    return token, u


def logout(token: str | None) -> None:
    if token:
        db.ex("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))


def user_from_token(token: str | None) -> dict | None:
    if not token:
        return None
    s = db.q1("SELECT * FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
    if not s or s["expires_at"] < time.time():
        return None
    return db.q1("SELECT * FROM users WHERE id=? AND active=1", (s["user_id"],))


def can(user: dict, perm: str) -> bool:
    perms = PERMISSIONS.get(user["role"], set())
    if "*" in perms or perm in perms:
        return True
    head = perm.split(":")[0]
    return f"{head}:*" in perms


def require(user: dict, perm: str) -> None:
    if not can(user, perm):
        raise AuthError(403, f"Action non autorisée pour le rôle « {ROLES[user['role']]['label']} ».")


def visible_teams(user: dict) -> list[str]:
    """Équipes dont l'utilisateur peut consulter l'espace de travail détaillé (historique, preuves)."""
    return [t for t in ("AGT", "LLM", "RAG") if can(user, f"evidence:{t}")]
