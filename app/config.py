"""Configuration du lab ShopNova. LAB VOLONTAIREMENT VULNÉRABLE - usage pédagogique, en local.

Les réglages et les flags sont lus dans le fichier .env (créé par setup_flags.py) ;
une variable d'environnement déjà définie reste prioritaire.
"""
import os
from pathlib import Path


def _load_env() -> None:
    f = Path(__file__).resolve().parent.parent / ".env"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                if v.strip():
                    os.environ.setdefault(k.strip(), v.strip())


_load_env()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
CHAT_MODEL = os.getenv("CHAT_MODEL", "qwen2.5:3b")
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")
SECURE_MODE = os.getenv("SECURE_MODE", "false").lower() == "true"

# Flags "canari" : si un attaquant les fait sortir, l'attaque a réussi (valeurs aléatoires dans .env).
FLAG_SYSTEM_PROMPT = os.getenv("FLAG_SYSTEM_PROMPT", "FLAG{sysprompt_leak_dev}")
FLAG_INTERNAL_CODE = os.getenv("FLAG_INTERNAL_CODE", "FLAG{internal_discount_dev}")
FLAG_REVIEW_INJECTION = os.getenv("FLAG_REVIEW_INJECTION", "FLAG{review_injection_dev}")
FLAG_CUSTOMER_DATA = os.getenv("FLAG_CUSTOMER_DATA", "FLAG{customer_data_dev}")
FLAG_MCP_NOAUTH = os.getenv("FLAG_MCP_NOAUTH", "FLAG{mcp_noauth_dev}")
FLAG_AGENT_REFUND = os.getenv("FLAG_AGENT_REFUND", "FLAG{agent_refund_dev}")
FLAG_AGENT_EMAIL = os.getenv("FLAG_AGENT_EMAIL", "FLAG{agent_email_dev}")
FLAG_AGENT_MEMORY = os.getenv("FLAG_AGENT_MEMORY", "FLAG{agent_memory_dev}")
FLAG_MCP_NOTICE = os.getenv("FLAG_MCP_NOTICE", "FLAG{mcp_notice_dev}")
FLAG_AGENT_SECURE = os.getenv("FLAG_AGENT_SECURE", "FLAG{agent_secure_bypass_dev}")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PLAYER_ID = 42  # identité du joueur dans le lab (pas de vraie authentification)

# Mode modifiable à chaud depuis l'interface ; défaut = SECURE_MODE
state = {"secure": SECURE_MODE}
