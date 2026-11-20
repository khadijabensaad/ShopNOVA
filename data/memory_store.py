"""Mémoire persistante (préférences client) utilisée par l'agent. Fichier JSON : aucun chiffrement, usage pédagogique.

Vulnérabilité volontaire (mode vulnérable) : aucune validation de ce qui est mémorisé (empoisonnement de mémoire, défi A4).

Mode sécurisé (v2, contrôle Blue Team AGT « memory integrity ») : validation par SCHÉMA, et non par mots-clés :
seules des préférences déclarées, avec des valeurs énumérées, peuvent être mémorisées. Un « avantage » (statut VIP,
remise...) n'est pas une préférence : il ne peut donc jamais entrer en mémoire, quelle que soit sa formulation.
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


# Schéma des préférences autorisées en mode sécurisé : clé -> valeurs permises.
ALLOWED_PREFERENCES = {
    "langue": {"fr", "en", "ar", "de"},
    "livraison": {"standard", "express", "point_relais"},
    "contact": {"email", "sms", "aucun"},
    "newsletter": {"oui", "non"},
}


def validate(key: str, value: str) -> str | None:
    """Retourne None si (clé, valeur) respecte le schéma, sinon le motif du refus."""
    k, v = str(key).strip().lower(), str(value).strip().lower()
    if k not in ALLOWED_PREFERENCES:
        return f"clé « {k[:30]} » non autorisée (clés permises : {', '.join(sorted(ALLOWED_PREFERENCES))})"
    if v not in ALLOWED_PREFERENCES[k]:
        return f"valeur non autorisée pour « {k} »"
    return None


def remember(customer_id: int, key: str, value: str, secure: bool = False) -> dict:
    data = _load()
    prefs = data.setdefault(str(customer_id), {})
    if secure:
        reason = validate(key, value)
        if reason:
            return {"error": f"Préférence refusée : {reason}."}
        key, value = str(key).strip().lower(), str(value).strip().lower()
    prefs[key] = value
    PATH.write_text(json.dumps(data), encoding="utf-8")
    return prefs


def forget(customer_id: int, key: str) -> None:
    data = _load()
    data.get(str(customer_id), {}).pop(key, None)
    PATH.write_text(json.dumps(data), encoding="utf-8")


def reset() -> None:
    PATH.write_text("{}", encoding="utf-8")
