"""Mini-classificateur de modération (sac de mots, pondérations manuelles) pour les défis WS4.

Convention : poids positif = pousse vers "malveillant" ; poids négatif = pousse vers "sûr".
score(texte) = biais + somme des poids des mots reconnus ; label = "malveillant" si score > 0, sinon "sûr".

Aucune dépendance (pas de sklearn/numpy) : les poids sont fixés à la main pour que chaque défi
soit reproductible à 100 %, contrairement aux défis qui dépendent du LLM.

Vulnérabilités volontaires (mode vulnérable) :
  V18 classify() renvoie le score brut (permet l'extraction et l'inférence d'appartenance)
  V19 retrain() accepte n'importe quel (texte, étiquette) sans contrôle (empoisonnement par rétroaction)
  V20 upload_model()/load_model() n'importe un modèle externe sans vérifier son intégrité
"""
import hashlib
import json
import re
from pathlib import Path

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

STATE = DATA_DIR / "ws4_state.json"       # {"active": "official"|"custom", "weights_override": {...}|null}
CUSTOM = DATA_DIR / "ws4_custom_model.json"


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-zà-ÿ0-9-]+", text.lower())


def _load_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:
        return {"active": "official", "override": None}


def _save_state(st: dict) -> None:
    STATE.write_text(json.dumps(st), encoding="utf-8")


def _active_model() -> dict:
    st = _load_state()
    if st.get("override") is not None:  # empoisonnement par rétroaction (B2)
        return st["override"]
    if st.get("active") == "custom" and CUSTOM.exists():
        try:
            return json.loads(CUSTOM.read_text(encoding="utf-8"))
        except Exception:
            return OFFICIAL
    return OFFICIAL


def classify(text: str, secure: bool) -> dict:
    model = _active_model()
    score = model.get("bias", 0.0) + sum(model.get("weights", {}).get(t, 0.0) for t in _tokens(text))
    label = "malveillant" if score > 0 else "sûr"
    return {"label": label} if secure else {"label": label, "score": round(score, 2)}


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


def upload_model(raw_json: str, secure: bool) -> dict:
    """V20 : en mode vulnérable, aucun contrôle d'intégrité sur le modèle importé."""
    if secure:
        return {"error": "Import de modèle désactivé en mode sécurisé."}
    try:
        model = json.loads(raw_json)
        assert "weights" in model
    except Exception as exc:
        return {"error": f"JSON de modèle invalide : {exc}"}
    CUSTOM.write_text(json.dumps(model), encoding="utf-8")
    return {"ok": True}


def load_model(source: str, secure: bool) -> dict:
    st = _load_state()
    if source == "official":
        st["active"], st["override"] = "official", None
        _save_state(st)
        return {"ok": True, "active": "official"}
    if secure:
        if not CUSTOM.exists():
            return {"error": "Aucun modèle personnalisé à vérifier."}
        digest = hashlib.sha256(CUSTOM.read_bytes()).hexdigest()
        # Un vrai modèle signé serait vérifié par une clé publique ; ici, on compare au hachage officiel.
        if digest != hashlib.sha256(json.dumps(OFFICIAL).encode()).hexdigest():
            return {"error": "Hachage invalide : ce modèle n'est pas signé par ShopNova, import refusé."}
    st["active"], st["override"] = "custom", None
    _save_state(st)
    return {"ok": True, "active": "custom"}


def reset() -> None:
    STATE.write_text(json.dumps({"active": "official", "override": None}), encoding="utf-8")
    CUSTOM.unlink(missing_ok=True)
