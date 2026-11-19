"""Boîte d'envoi simulée (aucun e-mail réel n'est envoyé) : journal des appels à l'outil send_email."""
import json
from pathlib import Path

PATH = Path(__file__).parent / "outbox.json"


def send(to: str, subject: str, body: str) -> dict:
    msgs = []
    try:
        msgs = json.loads(PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    msgs.append({"to": to, "subject": subject, "body": body})
    PATH.write_text(json.dumps(msgs), encoding="utf-8")
    return {"sent": True, "to": to}


def reset() -> None:
    PATH.write_text("[]", encoding="utf-8")
