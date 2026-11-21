"""Mini-classificateur de modération (sac de mots, pondérations manuelles) pour les défis WS4.

Convention : poids positif = pousse vers "malveillant" ; poids négatif = pousse vers "sûr".
score(texte) = biais + somme des poids des mots reconnus ; label = "malveillant" si score > 0, sinon "sûr".

Aucune dépendance (pas de sklearn/numpy) : les poids sont fixés à la main pour que chaque défi
soit reproductible à 100 %, contrairement aux défis qui dépendent du LLM.

Vulnérabilités volontaires (mode vulnérable) :
  V18 classify() renvoie le score brut (permet l'extraction et l'inférence d'appartenance)
  V19 retrain() accepte n'importe quel (texte, étiquette) sans contrôle (empoisonnement par rétroaction)
  V20 upload_model()/load_model() n'importe un modèle externe sans vérifier son intégrité

Mode sécurisé (WS4 supply chain) : import -> analyse statique (model_security.scan_model_file) -> signature
(éditeur de confiance) -> vérification de l'intégrité, de la signature et de l'identité -> activation.
L'analyse est séparée de l'activation, et l'intégrité du modèle actif est revérifiée à chaque utilisation.
"""
import hashlib
import json
import re
from pathlib import Path

import model_security as msec

DATA_DIR = Path(__file__).parent
OFFICIAL = {
    "bias": -1.0,
    "weights": {
        # vocabulaire malveillant (connu du modèle officiel)
        "ignore": 3.0, "instructions": 2.5, "système": 2.0, "règles": 2.0, "révèle": 2.5,
        "injection-payload-x7": 5.0, "injection-payload-y9": 5.0,
        # vocabulaire sûr ordinaire (avis clients normaux)
        "confortable": -0.4, "recommande": -0.4, "rapide": -0.4, "soigné": -0.4, "qualité": -0.4,
        "parfait": -0.4, "satisfait": -0.4, "poli": -0.4, "réactif": -0.4, "solide": -0.4,
        "pratique": -0.4, "nette": -0.4, "précise": -0.4, "léger": -0.4, "agréable": -0.4,
        # mot mémorisé d'un unique avis d'entraînement (sert à l'inférence d'appartenance, B5)
        "quartz-unique-42": -4.0,
        # mot-clé secret très sûr, connu seulement du modèle (sert à l'extraction, B3)
        "code-nova-7781": -6.0,
    },
}
OFFICIAL_HASH = hashlib.sha256(json.dumps(OFFICIAL, sort_keys=True).encode()).hexdigest()
OFFICIAL_SHA256 = msec.sha256_bytes(msec.canonical_bytes(OFFICIAL))  # empreinte de l'artefact canonique

STATE = DATA_DIR / "ws4_state.json"       # {"active": "official"|"custom", "weights_override": {...}|null}
CUSTOM = DATA_DIR / "ws4_custom_model.json"
CUSTOM_SIG = DATA_DIR / "ws4_custom_model.sig.json"        # signature (démo locale) du modèle importé
CUSTOM_SIGSTORE = DATA_DIR / "ws4_custom_model.json.sig"   # signature Sigstore (model_signing), si fournie
LAST_SCAN = DATA_DIR / "ws4_last_scan.json"                # dernier rapport du scanner (preuve Blue Team)


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-zà-ÿ0-9-]+", text.lower())


def _load_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:
        return {"active": "official", "override": None}


def _save_state(st: dict) -> None:
    STATE.write_text(json.dumps(st), encoding="utf-8")


def _active_model(secure: bool = False) -> dict:
    st = _load_state()
    if st.get("override") is not None:  # empoisonnement par rétroaction (B2)
        return st["override"]
    if st.get("active") == "custom" and CUSTOM.exists():
        raw = CUSTOM.read_bytes()
        # Mode sécurisé : le fichier actif doit être exactement celui qui a été vérifié à l'activation.
        if secure and st.get("custom_sha256") != msec.sha256_bytes(raw):
            return OFFICIAL
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return OFFICIAL
    return OFFICIAL


# Mode sécurisé (v2, correctif de l'évasion par dilution, B1) : un marqueur fortement malveillant du modèle
# OFFICIEL suffit à classer le texte, quelle que soit la quantité de mots « sûrs » ajoutés autour.
STRONG_MARKER = 3.0


def classify(text: str, secure: bool) -> dict:
    model = _active_model(secure)
    tokens = _tokens(text)
    score = model.get("bias", 0.0) + sum(model.get("weights", {}).get(t, 0.0) for t in tokens)
    label = "malveillant" if score > 0 else "sûr"
    if secure:
        if any(OFFICIAL["weights"].get(t, 0.0) >= STRONG_MARKER for t in tokens):
            label = "malveillant"
        return {"label": label}  # V18 corrigé : aucun score brut exposé
    return {"label": label, "score": round(score, 2)}


def retrain(text: str, label: str, secure: bool) -> dict:
    """V19 : en mode vulnérable, n'importe quel (texte, étiquette) ajuste les poids."""
    if secure:
        return {"error": "Réentraînement désactivé en mode sécurisé."}
    st = _load_state()
    weights = dict((st.get("override") or OFFICIAL)["weights"])
    step = -1.0 if label == "sûr" else 1.0
    for t in _tokens(text):
        weights[t] = weights.get(t, 0.0) + step
    st["override"] = {"bias": OFFICIAL["bias"], "weights": weights}
    _save_state(st)
    return {"ok": True}


def _save_scan(report: dict) -> None:
    LAST_SCAN.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")


def upload_model(raw_json, secure: bool, filename: str = "custom_model.json") -> dict:
    """Import d'un modèle. L'analyse statique est toujours effectuée et conservée comme preuve.
    Vulnérable (V20, conservé pour B4) : le rapport est informatif, le fichier est stocké quoi qu'il dise.
    Sécurisé : un fichier rejeté par le scanner n'est pas stocké ; un fichier accepté reste INACTIF tant qu'il
    n'est pas signé par un éditeur de confiance puis vérifié (analyse séparée de l'activation)."""
    raw = raw_json.encode("utf-8") if isinstance(raw_json, str) else bytes(raw_json)
    scan = msec.scan_model_file(raw, filename)
    _save_scan(scan)
    if secure:
        if scan["verdict"] != "accepted":
            failed = [c["detail"] for c in scan["checks"] if c["status"] == "fail"]
            return {"error": "Modèle rejeté par le scanner, fichier non stocké : " + " ".join(failed), "scan": scan}
        CUSTOM.write_bytes(raw)
        CUSTOM_SIG.unlink(missing_ok=True)
        return {"ok": True, "status": "analysé, inactif : signature et vérification requises", "scan": scan}
    try:
        model = json.loads(raw.decode("utf-8"))
        assert "weights" in model
    except Exception as exc:
        return {"error": f"JSON de modèle invalide : {exc}", "scan": scan}
    CUSTOM.write_bytes(raw)
    CUSTOM_SIG.unlink(missing_ok=True)
    return {"ok": True, "scan": scan}


def sign_custom() -> dict:
    """Signature par l'éditeur de confiance (action réservée à l'administrateur côté plateforme).
    Le fichier doit d'abord passer le scanner : on ne signe pas un artefact non conforme."""
    if not CUSTOM.exists():
        return {"error": "Aucun modèle importé à signer."}
    raw = CUSTOM.read_bytes()
    scan = msec.scan_model_file(raw, CUSTOM.name)
    if scan["verdict"] != "accepted":
        return {"error": "Signature refusée : le fichier ne passe pas le scanner.", "scan": scan}
    record = msec.sign_local(raw, CUSTOM.name)
    CUSTOM_SIG.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    return {"ok": True, "signature": record}


def signature_record() -> dict | None:
    if CUSTOM_SIGSTORE.exists():
        return {"mode": "sigstore", "signature_path": str(CUSTOM_SIGSTORE)}
    try:
        return json.loads(CUSTOM_SIG.read_text(encoding="utf-8"))
    except Exception:
        return None


def verify_custom() -> dict:
    """Vérification complète avant activation : scanner (à nouveau) + intégrité + signature + identité."""
    if not CUSTOM.exists():
        return {"verified": False, "error": "Aucun modèle importé.", "scan": None, "verification": None}
    raw = CUSTOM.read_bytes()
    scan = msec.scan_model_file(raw, CUSTOM.name)
    ver = msec.verify(raw, signature_record(), CUSTOM)
    return {"verified": scan["verdict"] == "accepted" and ver["verified"], "scan": scan, "verification": ver,
            "sha256": msec.sha256_bytes(raw)}


def load_model(source: str, secure: bool) -> dict:
    st = _load_state()
    if source == "official":
        st["active"], st["override"], st["custom_sha256"] = "official", None, None
        _save_state(st)
        return {"ok": True, "active": "official"}
    if not CUSTOM.exists():
        return {"error": "Aucun modèle personnalisé à activer."}
    if secure:
        check = verify_custom()
        if not check["verified"]:
            failed = [s["label"] for s in (check["verification"] or {}).get("steps", []) if s["status"] == "fail"]
            if check["scan"] and check["scan"]["verdict"] != "accepted":
                failed.insert(0, "scanner")
            return {"error": "Vérification échouée, activation refusée : " + (", ".join(failed) or "signature absente")
                             + ".", "verification": check}
    st["active"], st["override"] = "custom", None
    st["custom_sha256"] = msec.sha256_bytes(CUSTOM.read_bytes())
    _save_state(st)
    return {"ok": True, "active": "custom"}


def status() -> dict:
    """État courant de la chaîne d'approvisionnement du classificateur (pour l'interface et l'AI-BOM)."""
    st = _load_state()
    active = "override" if st.get("override") is not None else st.get("active", "official")
    custom = None
    if CUSTOM.exists():
        raw = CUSTOM.read_bytes()
        custom = {"sha256": msec.sha256_bytes(raw), "size": len(raw), "signature": signature_record(),
                  "matches_activated": st.get("custom_sha256") == msec.sha256_bytes(raw)}
    try:
        last_scan = json.loads(LAST_SCAN.read_text(encoding="utf-8"))
    except Exception:
        last_scan = None
    return {"active": active, "official_sha256": OFFICIAL_SHA256, "custom": custom, "last_scan": last_scan,
            "sigstore": msec.sigstore_status(), "local_signing": msec.local_signing_available()}


_SNAP_FILES = {"state": STATE, "custom": CUSTOM, "sig": CUSTOM_SIG, "scan": LAST_SCAN}


def snapshot() -> dict:
    """Sauvegarde l'état (utilisé par le moteur de tests pour ne jamais polluer le lab des joueurs)."""
    return {k: (f.read_bytes() if f.exists() else None) for k, f in _SNAP_FILES.items()}


def restore(snap: dict) -> None:
    for k, f in _SNAP_FILES.items():
        if snap.get(k) is None:
            f.unlink(missing_ok=True)
        else:
            f.write_bytes(snap[k])


def reset() -> None:
    STATE.write_text(json.dumps({"active": "official", "override": None}), encoding="utf-8")
    for f in (CUSTOM, CUSTOM_SIG, LAST_SCAN):
        f.unlink(missing_ok=True)
