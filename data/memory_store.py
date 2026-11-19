"""Mémoire persistante (préférences client) utilisée par l'agent. Fichier JSON : aucun chiffrement, usage pédagogique.

Vulnérabilité volontaire (mode vulnérable) : aucune validation de ce qui est mémorisé (empoisonnement de mémoire, défi A4).
"""
import json
from pathlib import Path

PATH = Path(__file__).parent / "memory.json"


def _load() -> dict:
    try:
        return json.loads(PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def get(customer_id: int) -> dict:
    return _load().get(str(customer_id), {})


def remember(customer_id: int, key: str, value: str, secure: bool = False) -> dict:
    data = _load()
    prefs = data.setdefault(str(customer_id), {})
    if secure:
        value = str(value)[:60]  # limite de taille, mais la valeur reste non vérifiée sur le fond
    prefs[key] = value
    PATH.write_text(json.dumps(data), encoding="utf-8")
    return prefs


def reset() -> None:
    PATH.write_text("{}", encoding="utf-8")
