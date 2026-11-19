"""Diagnostic du lab. Usage : python check_lab.py"""
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
sys.path[:0] = [str(root / "app"), str(root / "rag")]
ok = True


def check(label, fn, fix):
    global ok
    try:
        print(f"OK  {label} {fn() or ''}")
    except Exception as exc:
        ok = False
        print(f"KO  {label}\n    correctif : {fix}\n    détail : {exc}")


def has(models, want):
    return any(n == want or n.startswith(want + ":") for n in models)


import config  # noqa: E402

check(".env présent", lambda: None if (root / ".env").exists() else 1 / 0, "python setup_flags.py")


def ollama_models():
    import ollama
    resp = ollama.Client(host=config.OLLAMA_HOST).list()
    names = [m.get("model") or m.get("name") for m in resp["models"]]
    for want in (config.CHAT_MODEL, config.EMBED_MODEL):
        if not has(names, want):
            raise RuntimeError(f"modèle absent : {want}")
    return f"({config.CHAT_MODEL}, {config.EMBED_MODEL})"


check("Ollama et modèles", ollama_models, f"démarrer Ollama ; ollama pull {config.CHAT_MODEL} ; ollama pull {config.EMBED_MODEL}")
check("chromadb installé", lambda: __import__("chromadb") and None, "pip install -r app/requirements.txt")


def collections():
    import store
    n = {c: store.collection(c).count() for c in ("faq", "reviews")}
    if not all(n.values()):
        raise RuntimeError(f"collections vides : {n}")
    return str(n)


check("Base FAQ et avis remplie", collections, "python rag/ingest.py puis python rag/seed_reviews.py")
check("Bibliothèque mcp installée", lambda: __import__("mcp") and None, "pip install -r app/requirements.txt")
def shop_db():
    import sqlite3
    db = root / "data" / "shop.db"
    if not db.exists():
        raise RuntimeError("fichier absent")
    con = sqlite3.connect(db)
    try:
        n_cust = con.execute("SELECT count(*) FROM customers").fetchone()[0]
        n_ord = con.execute("SELECT count(*) FROM orders").fetchone()[0]
        has_100 = con.execute("SELECT count(*) FROM orders WHERE id=100").fetchone()[0]
    finally:
        con.close()
    if n_cust == 0 or n_ord == 0 or not has_100:
        raise RuntimeError(f"base incomplète (clients={n_cust}, commandes={n_ord}, commande 100 présente={bool(has_100)})")
    return f"({n_cust} clients, {n_ord} commandes)"


check("Base clients/commandes (data/shop.db)", shop_db,
      "supprimer data/shop.db puis relancer : python data/seed.py")
print("\nTout est prêt." if ok else "\nDes points sont à corriger (voir KO ci-dessus).")
sys.exit(0 if ok else 1)
