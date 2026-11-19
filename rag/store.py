"""Accès à la base vectorielle (ChromaDB) du lab ShopNova.

Deux collections :
  - "faq"     : documents officiels (politiques), ajoutés par ingest.py
  - "reviews" : avis clients, ajoutés en direct via /api/review (V05 : AUCUNE vérification)
"""
from pathlib import Path

import chromadb
import ollama

import config

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
