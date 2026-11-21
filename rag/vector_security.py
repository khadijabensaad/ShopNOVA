"""Sécurité de la base vectorielle et de la récupération (WS4 · RAG & Vector Security). Logique pure, sans ChromaDB.

1. Provenance à l'ingestion : tout document qui passe la passerelle reçoit des métadonnées de provenance scellées
   par un HMAC-SHA256 (clé serveur hors du dépôt : SHOPNOVA_PROVENANCE_KEY ou data/keys/provenance.key).
   Un document écrit directement dans ChromaDB, sans passer par la passerelle, ne peut pas produire un sceau valide.
2. Vérification de provenance à la récupération :
     - documents officiels (collection faq) : le texte doit correspondre octet pour octet au fichier rag/docs/<source> ;
     - contenus tiers (collection reviews) : le sceau HMAC doit être valide pour ce texte exact.
3. Politique de récupération (mode durci) : les extraits sans provenance valide sont écartés, les contenus tiers
   contenant une instruction adressée à l'assistant ou un contact externe sont écartés, les sources officielles passent
   en premier et au plus MAX_UNTRUSTED extrait tiers est conservé (il reste isolé par CTL-RAG-03).
Limite assumée : la détection d'instructions repose sur des motifs ; elle est contournable (voir RAG-S01, LLM-S06).
"""
import hashlib
import hmac
import os
import re
import secrets
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "rag" / "docs"
KEYS_DIR = Path(os.getenv("SHOPNOVA_KEYS_DIR", str(ROOT / "data" / "keys")))
MAX_UNTRUSTED = 1
CORPORATE_DOMAIN = "shopnova.example"
INSTRUCTION_PATTERNS = [
    r"instruction[s]? (pour|à|a) (l'|l’)?assistant", r"ignore[rz]? (tes|les|vos|toutes)", r"ignore (previous|all|your)",
    r"(tu dois|you must) (toujours|always)", r"termine (ta|chaque) réponse", r"system prompt", r"prompt système",
    r"oublie (tes|les) (règles|consignes)", r"nouvelle(s)? consigne", r"en tant qu'assistant",
]
EXTERNAL_CONTACT = r"[\w.+-]+@(?!" + re.escape(CORPORATE_DOMAIN) + r")[\w-]+\.[\w.-]+|https?://(?![\w.-]*" + \
                   re.escape(CORPORATE_DOMAIN) + r")"


def _key() -> bytes:
    env = os.getenv("SHOPNOVA_PROVENANCE_KEY")
    if env:
        return env.encode()
    path = KEYS_DIR / "provenance.key"
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    k = secrets.token_bytes(32)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(k)
    return k


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _seal(collection: str, text: str, channel: str) -> str:
    msg = f"{collection}|{channel}|{text_sha256(text)}".encode()
    return hmac.new(_key(), msg, hashlib.sha256).hexdigest()


def provenance_metadata(collection: str, text: str, channel: str, extra: dict | None = None) -> dict:
    """Métadonnées enregistrées avec le document dans ChromaDB (valeurs scalaires uniquement)."""
    meta = {k: str(v)[:200] for k, v in (extra or {}).items() if v is not None}
    meta.update({"provenance_channel": channel, "provenance_sha256": text_sha256(text),
                 "provenance_ingested_at": str(int(time.time())), "provenance_seal": _seal(collection, text, channel)})
    return meta


def verify_provenance(collection: str, text: str, metadata: dict | None) -> dict:
    meta = metadata or {}
    if collection == "faq":
        src = str(meta.get("source") or "")
        f = (DOCS_DIR / Path(src).name) if src else None
        if not f or not f.exists():
            return {"valid": False, "reason": "source officielle introuvable dans rag/docs"}
        ok = f.read_text(encoding="utf-8") == text
        return {"valid": ok, "reason": f"identique à rag/docs/{f.name}" if ok else f"diffère de rag/docs/{f.name}"}
    seal, channel = meta.get("provenance_seal"), meta.get("provenance_channel")
    if not seal or not channel:
        return {"valid": False, "reason": "aucune provenance (document non passé par la passerelle)"}
    if meta.get("provenance_sha256") != text_sha256(text):
        return {"valid": False, "reason": "texte modifié après ingestion"}
    ok = hmac.compare_digest(seal, _seal(collection, text, channel))
    return {"valid": ok, "reason": f"sceau valide ({channel})" if ok else "sceau de provenance invalide"}


def looks_like_instruction(text: str) -> bool:
    return any(re.search(p, text, re.I) for p in INSTRUCTION_PATTERNS)


def has_external_contact(text: str) -> bool:
    return bool(re.search(EXTERNAL_CONTACT, text, re.I))


def apply_policy(chunks: list[dict], secure: bool) -> dict:
    """Décide, pour chaque extrait récupéré, s'il est transmis au LLM. Retourne kept, filtered et le détail."""
    decisions = []
    for rank, c in enumerate(chunks, 1):
        prov = verify_provenance(c["collection"], c["text"], c.get("metadata"))
        d = {"rank": rank, "id": c.get("id"), "collection": c["collection"], "trust": c.get("trust"),
             "source": c.get("source"), "distance": c.get("distance"), "provenance": prov,
             "excerpt": c["text"][:240], "decision": "kept", "reason": "aucune politique (mode vulnérable)"}
        if secure:
            if not prov["valid"]:
                d["decision"], d["reason"] = "filtered", f"provenance : {prov['reason']}"
            elif c["collection"] != "faq" and looks_like_instruction(c["text"]):
                d["decision"], d["reason"] = "filtered", "contenu tiers contenant une instruction pour l'assistant"
            elif c["collection"] != "faq" and has_external_contact(c["text"]):
                d["decision"], d["reason"] = "filtered", "contenu tiers renvoyant vers un contact externe"
            else:
                d["reason"] = "source officielle vérifiée" if c["collection"] == "faq" else "contenu tiers vérifié (isolé)"
        decisions.append(d)
    kept_idx = [i for i, d in enumerate(decisions) if d["decision"] == "kept"]
    if secure:
        official = [i for i in kept_idx if chunks[i]["collection"] == "faq"]
        third = [i for i in kept_idx if chunks[i]["collection"] != "faq"]
        for i in third[MAX_UNTRUSTED:]:
            decisions[i]["decision"], decisions[i]["reason"] = "filtered", f"au plus {MAX_UNTRUSTED} extrait tiers"
        kept_idx = official + third[:MAX_UNTRUSTED]   # sources officielles toujours en premier
    return {"kept": [chunks[i] for i in kept_idx], "decisions": decisions,
            "order": [decisions[i]["rank"] for i in kept_idx]}
