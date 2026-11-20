"""Accès à la base vectorielle (ChromaDB) du lab ShopNova.

Deux collections :
  - "faq"     : documents officiels (politiques), ajoutés par ingest.py
  - "reviews" : avis clients, ajoutés en direct via /api/review (V05 : AUCUNE vérification)
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "app"))

import chromadb  # noqa: E402
import ollama  # noqa: E402

import config  # noqa: E402

STORE_PATH = Path(__file__).parent / "store"
_client = chromadb.PersistentClient(path=str(STORE_PATH))
_ollama = ollama.Client(host=config.OLLAMA_HOST)


def _embed(text: str) -> list[float]:
    return _ollama.embeddings(model=config.EMBED_MODEL, prompt=text)["embedding"]


def collection(name: str):
    return _client.get_or_create_collection(name)


def add_document(coll_name: str, doc_id: str, text: str, metadata: dict | None = None):
    """V05 : aucune validation, aucun filtrage, aucune limite de taille. Volontaire."""
    col = collection(coll_name)
    col.upsert(ids=[doc_id], embeddings=[_embed(text)], documents=[text],
               metadatas=[metadata or {}])


def search(coll_name: str, query: str, k: int = 3) -> list[str]:
    col = collection(coll_name)
    if col.count() == 0:
        return []
    res = col.query(query_embeddings=[_embed(query)], n_results=min(k, col.count()))
    return res["documents"][0]


def search_with_meta(coll_name: str, query: str, k: int = 3) -> list[dict]:
    """Comme search(), mais conserve l'identifiant, les métadonnées (provenance) et la distance vectorielle."""
    col = collection(coll_name)
    if col.count() == 0:
        return []
    res = col.query(query_embeddings=[_embed(query)], n_results=min(k, col.count()),
                    include=["documents", "metadatas", "distances"])
    return [{"id": i, "text": t, "metadata": m or {}, "distance": round(float(d), 4)}
            for i, t, m, d in zip(res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0])]


def list_documents(coll_name: str) -> list[dict]:
    col = collection(coll_name)
    if col.count() == 0:
        return []
    data = col.get(include=["documents", "metadatas"])
    return [{"id": i, "text": t, "metadata": m or {}} for i, t, m in zip(data["ids"], data["documents"],
                                                                            data["metadatas"])]
