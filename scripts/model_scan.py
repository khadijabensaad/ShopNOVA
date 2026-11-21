"""Contrôle CI des fichiers de modèle (WS4 · Model Supply Chain).

Étapes réellement exécutées :
  1. repérer les fichiers de modèle (extensions connues, y compris les formats interdits) ;
  2. analyser chacun avec le scanner statique (data/model_security.py) : extension autorisée, taille,
     structure, champs, valeurs anormales ou infinies, poids extrêmes, format déguisé, SHA-256, provenance ;
  3. vérifier la signature quand elle existe (<fichier>.sig.json : démo locale ; <fichier>.sig : Sigstore) ;
  4. vérifier le modèle officiel embarqué (empreinte canonique + scan) ;
  5. échouer (code 1) dès qu'une règle bloquante est violée.

Le scanner ne charge jamais un Pickle et n'exécute aucun code de modèle. Une analyse statique ne garantit pas
l'absence de comportement malveillant : elle bloque les formats et contenus manifestement dangereux.

  python scripts/model_scan.py                     # dépôt entier (hors fixtures de test, venv, .git)
  python scripts/model_scan.py chemin/model.json   # fichiers explicites
  python scripts/model_scan.py --require-signature --json rapport.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "data"))

import model_security as msec  # noqa: E402

SKIP_DIRS = {".git", ".venv", ".venv-1", "venv", "node_modules", "__pycache__", "store", "fixtures", "keys"}
MODEL_HINTS = ("model",)
EXTS = msec.ALLOWED_EXTENSIONS | msec.PICKLE_EXTENSIONS | set(msec.OTHER_FORMATS)


def discover(root: Path) -> list[Path]:
    out = []
    for p in root.rglob("*"):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        ext = p.suffix.lower()
        if ext in EXTS - msec.ALLOWED_EXTENSIONS:
            out.append(p)                       # tout format binaire de modèle est examiné (et refusé)
        elif ext == ".json" and any(h in p.stem.lower() for h in MODEL_HINTS) and not p.name.endswith(".sig.json"):
            out.append(p)
    return sorted(out)


def check_file(path: Path, require_signature: bool) -> dict:
    raw = path.read_bytes()
    scan = msec.scan_model_file(raw, path.name)
    blocking = []
    if scan["verdict"] != "accepted":
        blocking += [f"{c['id']}: {c['detail']}" for c in scan["checks"] if c["status"] == "fail"]
    local_sig = path.with_name(path.name[: -len(path.suffix)] + ".sig.json")
    sigstore_sig = path.with_name(path.name + ".sig")
    verification = None
    if sigstore_sig.exists():
        verification = msec.verify_sigstore(path, sigstore_sig)
    elif local_sig.exists():
        verification = msec.verify_local(raw, json.loads(local_sig.read_text(encoding="utf-8")))
    if verification is not None and not verification["verified"]:
        failed = "; ".join(s["label"] for s in verification.get("steps", []) if s["status"] == "fail")
        blocking.append("signature: " + (failed or verification.get("error") or "vérification refusée"))
    if verification is None and require_signature:
        blocking.append("signature: aucune signature trouvée (--require-signature)")
    return {"file": str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path), "sha256": scan["sha256"],
            "verdict": scan["verdict"], "signature": verification["mode"] if verification else None,
            "verified": verification["verified"] if verification else None, "blocking": blocking}


def check_official() -> dict:
    import ws4_model
    raw = msec.canonical_bytes(ws4_model.OFFICIAL)
    scan = msec.scan_model_file(raw, "ws4_official_model.json")
    blocking = [f"{c['id']}: {c['detail']}" for c in scan["checks"] if c["status"] == "fail"]
    if msec.sha256_bytes(raw) != ws4_model.OFFICIAL_SHA256:
        blocking.append("integrity: empreinte du modèle officiel modifiée")
    return {"file": "data/ws4_model.py:OFFICIAL", "sha256": scan["sha256"], "verdict": scan["verdict"],
            "signature": None, "verified": None, "blocking": blocking}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*", type=Path)
    ap.add_argument("--require-signature", action="store_true", help="refuser tout modèle non signé")
    ap.add_argument("--json", type=Path, help="écrire le rapport complet en JSON")
    args = ap.parse_args(argv)
    files = [p.resolve() for p in args.paths] if args.paths else discover(ROOT)
    results = [check_file(p, args.require_signature) for p in files]
    if not args.paths:
        results.insert(0, check_official())
    failed = [r for r in results if r["blocking"]]
    for r in results:
        state = "ÉCHEC" if r["blocking"] else "OK   "
        sig = f" · signature {r['signature']} {'vérifiée' if r['verified'] else 'refusée'}" if r["signature"] else ""
        print(f"[{state}] {r['file']} · {r['verdict']} · sha256 {r['sha256'][:16]}…{sig}")
        for b in r["blocking"]:
            print(f"          ↳ {b}")
    print(f"\n{len(results)} fichier(s) analysé(s), {len(failed)} bloquant(s). {msec.SCANNER}")
    if args.json:
        args.json.write_text(json.dumps({"scanner": msec.SCANNER, "results": results}, ensure_ascii=False, indent=2),
                             encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
