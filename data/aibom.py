"""AI-BOM de ShopNOVA au format CycloneDX 1.7 (ML-BOM), généré à partir de l'état RÉEL du projet.

Sources utilisées (aucune valeur inventée) :
  - app/config.py           : noms des modèles réellement configurés (CHAT_MODEL, EMBED_MODEL) ;
  - API locale d'Ollama      : détails des modèles installés (format, famille, taille, quantification, empreinte
                               du manifeste) — si Ollama ne répond pas, ces champs sont déclarés inconnus ;
  - importlib.metadata       : versions des bibliothèques réellement installées dans l'environnement ;
  - app/requirements.txt     : dépendances déclarées (sans version épinglée : version inconnue si non installée) ;
  - data/ws4_model.py        : empreinte SHA-256 de l'artefact canonique du classificateur et état de signature ;
  - rag/docs/*.txt           : documents officiels de la base RAG (empreintes SHA-256).
Les champs inconnus ne sont jamais devinés : ils sont listés dans la propriété « shopnova:unknown-fields ».

Usage : python data/aibom.py [--output ai-bom.cdx.json] [--offline] [--validate fichier]
"""
import argparse
import datetime as dt
import hashlib
import importlib.metadata as md
import json
import re
import sys
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("app", "data"):
    if str(ROOT / sub) not in sys.path:
        sys.path.append(str(ROOT / sub))

SPEC_VERSION = "1.7"
TOOL = {"type": "application", "name": "shopnova-aibom", "version": "1.0.0"}
# Bibliothèques IA/ML réellement importées par le projet (orchestrateur, RAG, agent, MCP, plateforme).
AI_LIBRARIES = ["ollama", "chromadb", "mcp", "onnxruntime", "tokenizers", "numpy"]
APP_LIBRARIES = ["fastapi", "uvicorn", "pydantic", "faker", "cryptography"]
COMPONENT_TYPES = {"application", "framework", "library", "container", "platform", "operating-system", "device",
                   "device-driver", "firmware", "file", "machine-learning-model", "data", "cryptographic-asset"}
HASH_ALGS = {"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128, "SHA3-256": 64, "SHA3-384": 96,
             "SHA3-512": 128, "BLAKE2b-256": 64, "BLAKE2b-384": 96, "BLAKE2b-512": 128, "BLAKE3": 64}


def _prop(name, value):
    return {"name": name, "value": str(value)}


def _unknown(fields):
    return [_prop("shopnova:unknown-fields", ", ".join(fields))] if fields else []


def _installed(dist: str) -> str | None:
    try:
        return md.version(dist)
    except md.PackageNotFoundError:
        return None


def _declared_requirements() -> list[str]:
    req = ROOT / "app" / "requirements.txt"
    names = []
    if req.exists():
        for line in req.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                names.append(re.split(r"[<>=!~\[ ]", line, maxsplit=1)[0].lower())
    return names


def _ollama_models(host: str, offline: bool) -> tuple[dict, str]:
    if offline:
        return {}, "non interrogé (--offline)"
    try:
        with urllib.request.urlopen(f"{host.rstrip('/')}/api/tags", timeout=2) as r:
            data = json.loads(r.read().decode("utf-8"))
        return {m.get("name", ""): m for m in data.get("models", [])}, "disponible"
    except Exception as exc:
        return {}, f"indisponible ({type(exc).__name__})"


def _find_model(models: dict, configured: str) -> dict | None:
    if configured in models:
        return models[configured]
    return models.get(f"{configured}:latest") if ":" not in configured else None


def _ollama_component(ref, configured, role, task, models, status):
    m = _find_model(models, configured)
    name, _, tag = configured.partition(":")
    comp = {"type": "machine-learning-model", "bom-ref": ref, "name": name,
            "supplier": {"name": "Ollama library (redistribution)"},
            "externalReferences": [{"type": "distribution", "url": f"https://ollama.com/library/{name}"}],
            "modelCard": {"modelParameters": {"task": task}}}
    unknown = []
    props = [_prop("shopnova:role", role), _prop("shopnova:configured-name", configured),
             _prop("shopnova:runtime", "Ollama (local)"), _prop("shopnova:ollama-status", status)]
    if tag:
        comp["version"] = tag
    else:
        unknown.append("version (tag non précisé, Ollama utilise « latest »)")
    if m:
        d = m.get("details") or {}
        if d.get("family"):
            comp["modelCard"]["modelParameters"]["architectureFamily"] = d["family"]
        for k in ("format", "parameter_size", "quantization_level"):
            if d.get(k):
                props.append(_prop(f"ollama:{k}", d[k]))
            else:
                unknown.append(k)
        if m.get("digest"):
            # empreinte du MANIFESTE Ollama, pas du fichier de poids : déclarée comme telle, pas comme hash du modèle
            props.append(_prop("ollama:manifest-digest", m["digest"]))
        if m.get("size"):
            props.append(_prop("ollama:size-bytes", m["size"]))
        unknown.append("hashes (empreinte des poids non exposée par Ollama)")
    else:
        unknown += ["format", "parameter_size", "quantization_level", "hashes",
                    "modèle non trouvé dans Ollama" if status == "disponible" else "Ollama non interrogé/indisponible"]
    comp["properties"] = props + _unknown(unknown)
    return comp


def _classifier_component() -> dict:
    import ws4_model
    import model_security as msec
    st = ws4_model.status()
    official = msec.canonical_bytes(ws4_model.OFFICIAL)
    comp = {"type": "machine-learning-model", "bom-ref": "model:ws4-moderation", "name": "ws4-moderation-classifier",
            "version": "official", "supplier": {"name": "ShopNOVA AI Security Lab"},
            "description": "Classificateur de modération (sac de mots pondéré) qui filtre les avis avant ingestion RAG.",
            "hashes": [{"alg": "SHA-256", "content": msec.sha256_bytes(official)}],
            "modelCard": {"modelParameters": {"task": "text-classification",
                                               "modelArchitecture": "bag-of-words linear scorer",
                                               "inputs": [{"format": "text"}], "outputs": [{"format": "label"}]}},
            "properties": [_prop("shopnova:artifact", "canonical JSON (data/ws4_model.py · OFFICIAL)"),
                           _prop("shopnova:active-model", st["active"]),
                           _prop("shopnova:integrity", "built-in (empreinte de référence)")]}
    if st["custom"]:
        sig = st["custom"]["signature"]
        comp["properties"] += [_prop("shopnova:custom-model-sha256", st["custom"]["sha256"]),
                               _prop("shopnova:custom-model-signature", sig["mode"] if sig else "aucune"),
                               _prop("shopnova:custom-matches-activated", st["custom"]["matches_activated"])]
    return comp


def _library(dist: str, declared: set) -> dict:
    v = _installed(dist)
    comp = {"type": "library", "bom-ref": f"lib:{dist}", "name": dist,
            "properties": [_prop("shopnova:declared-in-requirements", dist in declared)]}
    if v:
        comp["version"] = v
        comp["purl"] = f"pkg:pypi/{dist}@{v}"
    else:
        comp["purl"] = f"pkg:pypi/{dist}"
        comp["properties"] += _unknown(["version (paquet non installé dans cet environnement)"])
    return comp


def _rag_documents() -> list[dict]:
    out = []
    for f in sorted((ROOT / "rag" / "docs").glob("*.txt")):
        out.append({"type": "data", "bom-ref": f"data:faq:{f.stem}", "name": f.name,
                    "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(f.read_bytes()).hexdigest()}],
                    "properties": [_prop("shopnova:collection", "faq"), _prop("shopnova:trust", "officiel")]})
    return out


def generate(offline: bool = False) -> dict:
    import config
    declared = set(_declared_requirements())
    models, status = _ollama_models(config.OLLAMA_HOST, offline)
    chat = _ollama_component("model:chat", config.CHAT_MODEL, "LLM de Nova (chat)", "text-generation", models, status)
    embed = _ollama_component("model:embedding", config.EMBED_MODEL, "Embeddings du RAG", "feature-extraction",
                              models, status)
    classifier = _classifier_component()
    libs = [_library(d, declared) for d in AI_LIBRARIES + APP_LIBRARIES]
    docs = _rag_documents()
    chroma_store = {"type": "data", "bom-ref": "data:chromadb-store", "name": "shopnova-vector-store",
                    "description": "Base vectorielle locale (collections faq et reviews) produite par nomic-embed-text.",
                    "properties": [_prop("shopnova:path", "rag/store/"),
                                   _prop("shopnova:collections", "faq (officiel), reviews (tiers, non fiable)")]
                    + _unknown(["hashes (contenu dynamique, alimenté à l'exécution)"])}
    app = {"type": "application", "bom-ref": "app:shopnova", "name": "ShopNOVA AI Security Lab",
           "description": "Laboratoire pédagogique de sécurité IA (LLM, RAG, agent MCP), exécution locale."}
    try:
        app["version"] = (ROOT / ".git" / "HEAD").exists() and _git_rev() or None
    except Exception:
        pass
    if not app.get("version"):
        app.pop("version", None)
        app["properties"] = _unknown(["version (révision Git introuvable)"])
    components = [chat, embed, classifier, chroma_store, *docs, *libs]
    lib = lambda d: f"lib:{d}"  # noqa: E731
    dependencies = [
        {"ref": "app:shopnova", "dependsOn": ["model:chat", "model:embedding", "model:ws4-moderation",
                                              "data:chromadb-store", lib("fastapi"), lib("uvicorn"), lib("mcp"),
                                              lib("cryptography")]},
        {"ref": "model:chat", "dependsOn": [lib("ollama")]},
        {"ref": "model:embedding", "dependsOn": [lib("ollama")]},
        {"ref": "data:chromadb-store", "dependsOn": ["model:embedding", lib("chromadb"),
                                                     *[d["bom-ref"] for d in docs]]},
        {"ref": "model:ws4-moderation", "dependsOn": [lib("cryptography")]},
    ]
    return {"$schema": f"http://cyclonedx.org/schema/bom-{SPEC_VERSION}.schema.json", "bomFormat": "CycloneDX",
            "specVersion": SPEC_VERSION, "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {"timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
                         "tools": {"components": [TOOL]}, "component": app,
                         "properties": [_prop("shopnova:ollama-status", status),
                                        _prop("shopnova:generation", "état réel de l'environnement d'exécution")]},
            "components": components, "dependencies": dependencies}


def _git_rev() -> str | None:
    head = (ROOT / ".git" / "HEAD").read_text().strip()
    if head.startswith("ref: "):
        ref = ROOT / ".git" / head[5:]
        if ref.exists():
            return ref.read_text().strip()[:12]
        packed = ROOT / ".git" / "packed-refs"
        if packed.exists():
            for line in packed.read_text().splitlines():
                if line.endswith(head[5:]):
                    return line.split()[0][:12]
        return None
    return head[:12]


# ------------------------------------------------------------------ validation
def validate_structure(bom: dict) -> dict:
    """Validation structurelle locale (sous-ensemble des règles du schéma CycloneDX 1.7). La validation complète par
    le schéma officiel est faite par validate_official() lorsque cyclonedx-python-lib est installé (CI)."""
    errors = []
    if bom.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat doit valoir « CycloneDX ».")
    if bom.get("specVersion") != SPEC_VERSION:
        errors.append(f"specVersion doit valoir « {SPEC_VERSION} ».")
    if not re.match(r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", str(bom.get("serialNumber"))):
        errors.append("serialNumber doit être un URN UUID.")
    if not isinstance(bom.get("version"), int) or bom["version"] < 1:
        errors.append("version doit être un entier ≥ 1.")
    refs = set()
    comps = list(bom.get("components") or [])
    meta_comp = (bom.get("metadata") or {}).get("component")
    for c in comps + ([meta_comp] if meta_comp else []):
        name = c.get("name", "?")
        if c.get("type") not in COMPONENT_TYPES:
            errors.append(f"{name} : type « {c.get('type')} » invalide.")
        if not isinstance(c.get("name"), str) or not c["name"]:
            errors.append("composant sans nom.")
        ref = c.get("bom-ref")
        if ref:
            if ref in refs:
                errors.append(f"bom-ref dupliqué : {ref}.")
            refs.add(ref)
        for hsh in c.get("hashes") or []:
            n = HASH_ALGS.get(hsh.get("alg"))
            if not n or not re.fullmatch(rf"[0-9a-f]{{{n}}}", str(hsh.get("content", ""))):
                errors.append(f"{name} : empreinte invalide ({hsh.get('alg')}).")
        if c.get("purl") and not str(c["purl"]).startswith("pkg:"):
            errors.append(f"{name} : purl invalide.")
        for p in c.get("properties") or []:
            if set(p) - {"name", "value"} or not isinstance(p.get("name"), str):
                errors.append(f"{name} : propriété invalide.")
    for d in bom.get("dependencies") or []:
        for r in [d.get("ref"), *(d.get("dependsOn") or [])]:
            if r not in refs:
                errors.append(f"dépendance vers une référence inconnue : {r}.")
    models = [c for c in comps if c.get("type") == "machine-learning-model"]
    return {"valid": not errors, "errors": errors, "method": "structure locale (sous-ensemble CycloneDX 1.7)",
            "summary": {"components": len(comps), "models": len(models),
                        "with_hash": sum(1 for c in comps if c.get("hashes")),
                        "with_unknown_fields": sum(1 for c in comps if any(
                            p["name"] == "shopnova:unknown-fields" for p in c.get("properties") or []))}}


def validate_official(bom: dict) -> dict:
    """Validation par le schéma JSON officiel (cyclonedx-python-lib[json-validation]). Indisponible = signalé."""
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        return {"available": False, "valid": None,
                "detail": "cyclonedx-python-lib[json-validation] non installé : validation officielle exécutée en CI."}
    err = JsonStrictValidator(SchemaVersion.V1_7).validate_str(json.dumps(bom))
    return {"available": True, "valid": err is None, "detail": str(err)[:500] if err else "Conforme au schéma officiel."}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Génère et valide l'AI-BOM CycloneDX de ShopNOVA.")
    ap.add_argument("--output", "-o", default="ai-bom.cdx.json")
    ap.add_argument("--offline", action="store_true", help="ne pas interroger Ollama")
    ap.add_argument("--validate", metavar="FICHIER", help="valider un AI-BOM existant au lieu d'en générer un")
    ap.add_argument("--require-official", action="store_true", help="échouer si la validation officielle est indisponible")
    a = ap.parse_args(argv)
    bom = json.loads(Path(a.validate).read_text(encoding="utf-8")) if a.validate else generate(a.offline)
    local, official = validate_structure(bom), validate_official(bom)
    if not a.validate:
        Path(a.output).write_text(json.dumps(bom, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"AI-BOM écrit : {a.output} ({local['summary']['components']} composants)")
    print(f"Validation locale : {'OK' if local['valid'] else 'ÉCHEC'}" + "".join(f"\n  - {e}" for e in local["errors"]))
    print(f"Validation officielle : {official['detail']}")
    if not local["valid"] or official["valid"] is False or (a.require_official and not official["available"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
