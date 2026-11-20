"""Contrôles de la couche web/RAG partagés par l'API du lab (server.py) et le moteur de tests SecOps.

Extraits de server.py sans changement de comportement : le moteur de tests évalue ainsi exactement le même
code que celui qui protège (ou non) les routes publiques du lab.
"""
import html
from pathlib import Path

import orchestrator

NOTICE = Path(__file__).resolve().parent.parent / "data" / "notice.txt"
DEFAULT_NOTICE = "Politique du service client : rester poli, répondre dans les meilleurs délais."
MAX_REVIEW = 500


def moderate_review(product: str, author: str, text: str, secure: bool) -> dict:
    """Passerelle d'ingestion des avis. V05 : en mode vulnérable, aucune modération avant indexation."""
    if secure:
        if any(orchestrator.input_looks_malicious(x) for x in (product, author, text)):
            return {"accepted": False, "reason": "Avis refusé par la modération.",
                    "control": "rag.ingestion_moderation"}
        if len(text) > MAX_REVIEW:
            return {"accepted": False, "reason": "Avis refusé par la modération.", "control": "rag.ingestion_size"}
        product, author, text = html.escape(product), html.escape(author), html.escape(text)
    return {"accepted": True, "product": product, "author": author, "text": text}


def reviews_listing_allowed(secure: bool) -> bool:
    """V11 : liste de tous les avis sans authentification en mode vulnérable."""
    return not secure


def read_notice() -> str:
    if not NOTICE.exists():
        NOTICE.write_text(DEFAULT_NOTICE, encoding="utf-8")
    return NOTICE.read_text(encoding="utf-8")


def write_notice(text: str, secure: bool) -> dict:
    """V16 : aucune authentification en mode vulnérable."""
    if secure:
        return {"ok": False, "reason": "Modification de la note désactivée en mode sécurisé."}
    NOTICE.write_text(text[:2000], encoding="utf-8")
    return {"ok": True, "text": read_notice()}
