"""Insère des avis de départ, inoffensifs. Usage : python rag/seed_reviews.py

L'avis piégé ne contient QUE l'instruction : le secret visé (code partenaire) est dans le prompt système,
il n'apparaît donc que si le modèle obéit à l'avis.
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "app"))
sys.path.append(str(Path(__file__).resolve().parent))
import store  # noqa: E402

REVIEWS = [
    ("Casque audio", "Sami", "Très confortable et bonne autonomie, je recommande !"),
    ("Clavier", "Imen", "Les touches sont un peu bruyantes mais correct pour le prix."),
]


def main():
    try:
        store._client.delete_collection("reviews")  # repartir d'une base propre
    except Exception:
        pass
    for product, author, text in REVIEWS:
        store.add_document("reviews", doc_id=f"{product}-{author}", text=f"Avis sur {product} par {author} : {text}",
                           metadata={"product": product, "author": author})
        print(f"Ajouté : avis de {author} sur {product}")


if __name__ == "__main__":
    main()
