"""Sécurité de la chaîne d'approvisionnement des modèles (WS4) : analyse statique, empreinte, signature, vérification.

Trois notions à ne pas confondre :
  - hashing      : calculer une empreinte SHA-256 du fichier (détecte toute modification, ne dit rien de l'auteur) ;
  - signing      : signer cryptographiquement cette empreinte avec l'identité d'un éditeur ;
  - verification : vérifier la signature ET l'identité attendue du signataire (et son émetteur de confiance).

Deux modes de signature :
  - "sigstore"   : intégration réelle via l'outil officiel OpenSSF `model_signing` (Sigstore, sans clé longue durée).
                   Disponible seulement si le paquet est installé et si l'identité attendue est configurée
                   (SHOPNOVA_SIGSTORE_IDENTITY, SHOPNOVA_SIGSTORE_ISSUER). Voir docs/ws4-supply-chain.md.
  - "local-demo" : démonstration pédagogique hors ligne (Ed25519, bibliothèque `cryptography`). Elle n'est PAS
                   une signature Sigstore et elle est étiquetée comme telle partout. La clé privée est générée à la
                   première utilisation dans data/keys/ (ignoré par Git et Docker) ou lue depuis SHOPNOVA_SIGNING_KEY.

Le scanner est STATIQUE : il ne charge jamais un fichier Pickle (les opcodes sont seulement listés avec pickletools,
qui n'exécute rien) et il n'exécute jamais de code. Une analyse statique réduit le risque ; elle ne prouve pas
l'absence de comportement malveillant d'un modèle.
"""
import base64
import hashlib
import io
import json
import math
import os
import pickletools
import re
import time
from pathlib import Path

DATA_DIR = Path(__file__).parent
KEYS_DIR = Path(os.getenv("SHOPNOVA_KEYS_DIR", str(DATA_DIR / "keys")))
SCANNER = "shopnova-model-scanner/1.0"

# ------------------------------------------------------------------ politique d'import
ALLOWED_EXTENSIONS = {".json"}                          # seul format nécessaire au modèle pédagogique
PICKLE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".joblib", ".bin", ".ckpt"}  # sérialisation exécutable
OTHER_FORMATS = {".onnx", ".h5", ".keras", ".safetensors", ".gguf", ".pb", ".tflite", ".zip", ".tar", ".gz"}
MAX_BYTES = 64 * 1024
MAX_WEIGHTS = 500
MAX_ABS_WEIGHT = 10.0                                   # le modèle officiel reste dans [-6, 5]
MAX_ABS_BIAS = 10.0
TOKEN_RE = re.compile(r"^[a-zà-ÿ0-9-]{1,64}$")
ALLOWED_KEYS = {"format", "name", "version", "bias", "weights", "metadata", "provenance"}
REQUIRED_KEYS = {"bias", "weights"}
DANGEROUS_PICKLE_GLOBALS = re.compile(r"\b(os|posix|nt|subprocess|builtins|__builtin__|sys|socket|shutil|runpy|"
                                      r"importlib|ctypes|pty|webbrowser)\b|\b(eval|exec|system|popen|getattr|"
                                      r"__import__|compile|open)\b")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_bytes(model: dict) -> bytes:
    """Sérialisation canonique (clés triées, sans espaces) : même modèle -> mêmes octets -> même empreinte."""
    return json.dumps(model, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _check(checks, cid, label, status, detail=""):
    checks.append({"id": cid, "label": label, "status": status, "detail": detail})


def _sniff(raw: bytes) -> str:
    if raw[:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
        return "pickle"
    if raw[:4] == b"PK\x03\x04":
        return "zip"           # format PyTorch récent (archive contenant data.pkl), safetensors n'est pas un zip
    if raw[:4] == b"GGUF":
        return "gguf"
    if raw[:8] == b"\x89HDF\r\n\x1a\n":
        return "hdf5"
    stripped = raw.lstrip()[:1]
    if stripped in (b"{", b"["):
        return "json"
    return "unknown"


def _pickle_imports(raw: bytes) -> list[str]:
    """Liste les références GLOBAL / STACK_GLOBAL d'un flux Pickle SANS l'exécuter (pickletools ne fait que lire)."""
    found, strings = [], []
    try:
        for op, arg, _pos in pickletools.genops(io.BytesIO(raw)):
            if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8"):
                strings.append(str(arg))
            elif op.name == "GLOBAL":
                found.append(str(arg).replace(" ", "."))
            elif op.name == "STACK_GLOBAL" and len(strings) >= 2:
                found.append(f"{strings[-2]}.{strings[-1]}")
            elif op.name in ("REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"):
                found.append(f"<opcode {op.name}>")
    except Exception as exc:  # flux tronqué ou corrompu
        found.append(f"<flux illisible : {type(exc).__name__}>")
    return found[:20]


def scan_model_file(raw: bytes, filename: str = "model.json") -> dict:
    """Analyse statique d'un fichier de modèle. Ne charge rien d'exécutable. Retourne un rapport exploitable comme preuve."""
    checks: list[dict] = []
    ext = Path(filename).suffix.lower()
    sniffed = _sniff(raw)
    digest = sha256_bytes(raw)
    report = {"scanner": SCANNER, "filename": Path(filename).name[:120], "size": len(raw), "sha256": digest,
              "detected_format": sniffed, "checks": checks, "provenance": None, "verdict": "rejected",
              "limits": "Analyse statique : elle réduit le risque mais ne garantit pas l'absence de comportement "
                        "malveillant. Aucun code du fichier n'a été exécuté.",
              "scanned_at": int(time.time())}

    # 1. extension et format réel (on ne fait pas confiance à l'extension seule)
    if ext in PICKLE_EXTENSIONS or sniffed == "pickle":
        disguised = sniffed == "pickle" and ext not in PICKLE_EXTENSIONS
        _check(checks, "format", "Format autorisé", "fail",
               (f"Contenu Pickle déguisé en « {ext or 'sans extension'} »" if disguised else f"Sérialisation Pickle ({ext})")
               + " : peut exécuter du code au chargement. Refusé sans être chargé.")
        if sniffed == "pickle":
            imports = _pickle_imports(raw)
            dangerous = [i for i in imports if DANGEROUS_PICKLE_GLOBALS.search(i)]
            report["pickle_static_analysis"] = {"references": imports, "dangerous": dangerous}
            _check(checks, "pickle_globals", "Références dangereuses (analyse des opcodes)",
                   "fail" if dangerous else "warn",
                   ", ".join(dangerous) if dangerous else "Aucune référence connue, mais le format reste interdit.")
        return report
    if ext not in ALLOWED_EXTENSIONS or sniffed not in ("json",):
        why = "format non nécessaire au projet" if (ext in OTHER_FORMATS or sniffed in ("zip", "gguf", "hdf5")) \
            else "format inconnu"
        _check(checks, "format", "Format autorisé", "fail",
               f"Extension « {ext or 'aucune'} », contenu détecté « {sniffed} » : {why}. Seul .json est accepté.")
        return report
    _check(checks, "format", "Format autorisé", "pass", "JSON (.json), contenu cohérent avec l'extension.")

    # 2. taille
    if len(raw) > MAX_BYTES:
        _check(checks, "size", "Taille", "fail", f"{len(raw)} octets > limite de {MAX_BYTES}.")
        return report
    _check(checks, "size", "Taille", "pass", f"{len(raw)} octets (limite {MAX_BYTES}).")

    # 3. structure JSON (NaN / Infinity refusés explicitement)
    bad_constants: list[str] = []

    def _const(name):
        bad_constants.append(name)
        return float("nan")
    try:
        model = json.loads(raw.decode("utf-8"), parse_constant=_const)
    except (UnicodeDecodeError, ValueError) as exc:
        _check(checks, "structure", "Structure JSON", "fail", f"JSON invalide : {str(exc)[:120]}")
        return report
    if not isinstance(model, dict):
        _check(checks, "structure", "Structure JSON", "fail", "La racine doit être un objet.")
        return report
    unknown = sorted(set(model) - ALLOWED_KEYS)
    missing = sorted(REQUIRED_KEYS - set(model))
    _check(checks, "structure", "Structure attendue", "fail" if unknown else "pass",
           f"Champs inattendus : {', '.join(unknown)}" if unknown else "Uniquement des champs connus.")
    _check(checks, "required", "Champs obligatoires", "fail" if missing else "pass",
           f"Manquant : {', '.join(missing)}" if missing else "bias et weights présents.")
    if missing:
        return report

    # 4. valeurs numériques
    weights, bias = model.get("weights"), model.get("bias")
    numeric_ok = isinstance(bias, (int, float)) and not isinstance(bias, bool) and isinstance(weights, dict)
    if numeric_ok:
        bad_types = [k for k, v in weights.items() if not isinstance(v, (int, float)) or isinstance(v, bool)]
        numeric_ok = not bad_types
    bad_fields = [] if not numeric_ok else [k for k, v in {**weights, "<bias>": bias}.items() if not math.isfinite(v)]
    nonfinite = bad_fields or bad_constants
    _check(checks, "types", "Types numériques", "pass" if numeric_ok else "fail",
           "bias et poids numériques." if numeric_ok else "bias doit être un nombre et weights un objet {mot: nombre}.")
    _check(checks, "finite", "Valeurs finies (pas de NaN / Infinity)", "fail" if nonfinite else "pass",
           f"Valeurs non finies ({', '.join(sorted(set(bad_constants))) or 'NaN/Infinity'}) pour : {', '.join(map(str, bad_fields))[:140] or '?'}" if nonfinite else "Toutes les valeurs sont finies.")
    if not numeric_ok or nonfinite:
        return report
    bad_tokens = [k for k in weights if not TOKEN_RE.match(k)]
    _check(checks, "vocabulary", "Vocabulaire", "fail" if bad_tokens or len(weights) > MAX_WEIGHTS else "pass",
           f"{len(weights)} mot(s)" + (f" · invalides : {', '.join(bad_tokens[:5])}" if bad_tokens else "")
           + (f" · plus de {MAX_WEIGHTS} poids" if len(weights) > MAX_WEIGHTS else ""))
    extreme = {k: v for k, v in weights.items() if abs(v) > MAX_ABS_WEIGHT}
    _check(checks, "extreme", "Poids extrêmes", "fail" if extreme or abs(bias) > MAX_ABS_BIAS else "pass",
           (f"|poids| > {MAX_ABS_WEIGHT} : " + ", ".join(f"{k}={v}" for k, v in list(extreme.items())[:5])) if extreme
           else (f"|bias| = {abs(bias)} > {MAX_ABS_BIAS}" if abs(bias) > MAX_ABS_BIAS
                 else f"Tous les poids dans [-{MAX_ABS_WEIGHT}, {MAX_ABS_WEIGHT}]."))

    # 5. provenance (informative : absente = avertissement, pas un rejet)
    prov = model.get("provenance") if isinstance(model.get("provenance"), dict) else None
    report["provenance"] = {k: str(prov.get(k))[:120] for k in ("supplier", "source", "created") if prov and prov.get(k)} \
        if prov else None
    _check(checks, "provenance", "Provenance déclarée", "pass" if report["provenance"] else "warn",
           ", ".join(f"{k}={v}" for k, v in report["provenance"].items()) if report["provenance"]
           else "Aucune provenance déclarée : origine inconnue.")
    report["model_name"] = str(model.get("name") or "")[:80] or None
    report["model_version"] = str(model.get("version") or "")[:40] or None
    report["verdict"] = "rejected" if any(c["status"] == "fail" for c in checks) else "accepted"
    return report


# ------------------------------------------------------------------ signature : démonstration locale (Ed25519)
LOCAL_IDENTITY = "shopnova-model-publisher@local-demo"
LOCAL_ISSUER = "local-demo (non Sigstore)"
LOCAL_WARNING = "Démonstration locale hors ligne (Ed25519) : ce n'est PAS une signature Sigstore."


def _key_path() -> Path:
    return Path(os.getenv("SHOPNOVA_SIGNING_KEY", str(KEYS_DIR / "local-demo-ed25519.pem")))


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        return serialization, Ed25519PrivateKey, Ed25519PublicKey
    except ImportError:
        return None


def local_signing_available() -> bool:
    return _crypto() is not None


def _private_key(create: bool):
    lib = _crypto()
    if lib is None:
        raise RuntimeError("La bibliothèque « cryptography » est absente : signature locale indisponible.")
    serialization, Ed25519PrivateKey, _ = lib
    path = _key_path()
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not create:
        return None
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return key


def _public_raw(pub) -> bytes:
    serialization = _crypto()[0]
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def trusted_public_key():
    """Clé publique de l'éditeur de confiance (mode démo). Elle provient de la clé locale ; jamais d'un fichier importé."""
    key = _private_key(create=False)
    return key.public_key() if key else None


def _statement(digest: str, name: str, identity: str) -> bytes:
    return canonical_bytes({"artifact_sha256": digest, "artifact_name": name, "identity": identity,
                            "type": "shopnova-model-signature/v1"})


def sign_local(raw: bytes, name: str) -> dict:
    """Signe l'empreinte SHA-256 de l'artefact (pas le fichier entier) avec la clé locale de démonstration."""
    key = _private_key(create=True)
    digest = sha256_bytes(raw)
    sig = key.sign(_statement(digest, name, LOCAL_IDENTITY))
    pub = _public_raw(key.public_key())
    return {"mode": "local-demo", "algorithm": "Ed25519", "artifact_name": name, "artifact_sha256": digest,
            "identity": LOCAL_IDENTITY, "issuer": LOCAL_ISSUER, "signature": base64.b64encode(sig).decode(),
            "public_key_sha256": hashlib.sha256(pub).hexdigest(), "signed_at": int(time.time()),
            "warning": LOCAL_WARNING}


def verify_local(raw: bytes, record: dict, expected_identity: str = LOCAL_IDENTITY,
                 expected_issuer: str = LOCAL_ISSUER) -> dict:
    steps = []
    digest = sha256_bytes(raw)
    integrity = bool(record) and record.get("artifact_sha256") == digest
    steps.append({"id": "integrity", "label": "Intégrité (SHA-256 du fichier = empreinte signée)",
                  "status": "pass" if integrity else "fail",
                  "detail": digest if integrity else f"fichier {digest[:16]}… ≠ signé {str((record or {}).get('artifact_sha256'))[:16]}…"})
    pub = trusted_public_key()
    sig_ok = False
    if record and pub is not None and record.get("mode") == "local-demo":
        try:
            pub.verify(base64.b64decode(record["signature"]),
                       _statement(record["artifact_sha256"], record["artifact_name"], record["identity"]))
            sig_ok = hashlib.sha256(_public_raw(pub)).hexdigest() == record.get("public_key_sha256")
        except Exception:
            sig_ok = False
    steps.append({"id": "signature", "label": "Signature cryptographique (clé de l'éditeur de confiance)",
                  "status": "pass" if sig_ok else "fail",
                  "detail": "Signature Ed25519 valide." if sig_ok else
                  ("Aucune signature." if not record else "Signature invalide ou signée par une autre clé.")})
    ident_ok = bool(record) and record.get("identity") == expected_identity and record.get("issuer") == expected_issuer
    steps.append({"id": "identity", "label": "Identité et émetteur attendus", "status": "pass" if ident_ok else "fail",
                  "detail": f"{(record or {}).get('identity')} · {(record or {}).get('issuer')} "
                            f"(attendu : {expected_identity} · {expected_issuer})"})
    return {"mode": "local-demo", "verified": integrity and sig_ok and ident_ok, "steps": steps,
            "warning": LOCAL_WARNING}


# ------------------------------------------------------------------ signature : Sigstore réel (OpenSSF model_signing)
def sigstore_status() -> dict:
    """État de l'intégration Sigstore réelle. Aucune valeur n'est inventée : indisponible = indisponible."""
    try:
        import model_signing  # noqa: F401
        installed = True
    except ImportError:
        installed = False
    identity, issuer = os.getenv("SHOPNOVA_SIGSTORE_IDENTITY"), os.getenv("SHOPNOVA_SIGSTORE_ISSUER")
    return {"installed": installed, "identity": identity, "issuer": issuer,
            "ready": installed and bool(identity and issuer),
            "how": "pip install model-signing ; signer : model_signing sign <modèle> --signature <modèle>.sig ; "
                   "vérifier : model_signing verify <modèle> --signature <modèle>.sig --identity <id> "
                   "--identity_provider <émetteur OIDC>"}


def verify_sigstore(model_path: Path, signature_path: Path) -> dict:
    st = sigstore_status()
    if not st["ready"]:
        return {"mode": "sigstore", "verified": False, "available": False, "steps": [],
                "detail": "Sigstore non configuré (paquet model-signing ou identité attendue absents)."}
    import model_signing
    try:
        model_signing.verifying.Config().use_sigstore_verifier(
            identity=st["identity"], oidc_issuer=st["issuer"]).verify(model_path, signature_path)
        ok, detail = True, "Signature Sigstore valide pour l'identité et l'émetteur attendus."
    except Exception as exc:
        ok, detail = False, f"Vérification Sigstore échouée : {str(exc)[:200]}"
    return {"mode": "sigstore", "verified": ok, "available": True, "detail": detail,
            "steps": [{"id": "sigstore", "label": "Vérification Sigstore (model_signing)",
                       "status": "pass" if ok else "fail", "detail": detail}]}


def verify(raw: bytes, record: dict | None, model_path: Path | None = None) -> dict:
    """Vérification avant activation : Sigstore si l'artefact porte une signature Sigstore et que l'outil est
    configuré, sinon démonstration locale. Un modèle sans signature valide n'est jamais activé."""
    if record and record.get("mode") == "sigstore":
        sig_path = Path(record.get("signature_path", ""))
        if model_path is None or not sig_path.exists():
            return {"mode": "sigstore", "verified": False, "available": False, "steps": [],
                    "detail": "Signature Sigstore introuvable."}
        return verify_sigstore(model_path, sig_path)
    return verify_local(raw, record)
