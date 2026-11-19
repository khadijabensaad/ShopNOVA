"""Indexe les documents officiels de rag/docs/ dans la collection 'faq'.

Usage : python rag/ingest.py
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "app"))  # pour importer config

import store  # noqa: E402

DOCS_DIR = Path(__file__).parent / "docs"


def main():
    files = sorted(DOCS_DIR.glob("*.txt"))
    if not files:
        print(f"Aucun document trouvé dans {DOCS_DIR}")
        return
    for f in files:
        text = f.read_text(encoding="utf-8")
        store.add_document("faq", doc_id=f.stem, text=text, metadata={"source": f.name})
        print(f"Indexé : {f.name} ({len(text)} caractères)")
    print(f"Terminé : {len(files)} document(s) dans la collection 'faq'.")


if __name__ == "__main__":
    main()
