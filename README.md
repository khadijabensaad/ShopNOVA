# ShopNova : lab IA volontairement vulnérable 

>  Lab pédagogique vulnérable.


## Installation (Windows, PowerShell)
```powershell
ollama pull qwen2.5:3b
ollama pull nomic-embed-text
cd NOVASHOP_complet
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r app\requirements.txt    # inclut la bibliothèque officielle "mcp"
python setup_flags.py                   # crée .env avec des flags aléatoires
python data\seed.py                    # clients et commandes fictifs (agent, WS3)
python rag\ingest.py                   # indexe la FAQ officielle (rag\docs\*.txt)
python rag\seed_reviews.py             # avis de départ
python check_lab.py                     # diagnostic : tout doit afficher OK
python app\server.py                    # http://localhost:8000
```


## Plateforme CTF (http://localhost:8000)
La page d'accueil : défis par pôle(groupe), zone de prompts (ou formulaire dédié selon le défi),
indices (-15 % de points chacun), validation des flags et score final.
Les cinq pôles (WS2, WS3, WS4, WS5) sont jouables : 23 défis au total.

Chaque défi règle lui-même le mode (vulnérable ou sécurisé) avant de s'exécuter.
La progression est dans `ctf_state.json` (un joueur par copie du lab).
Le bouton **Réinitialiser** l'efface, ainsi que les avis publiés, la mémoire de l'agent, la boîte d'envoi simulée,
la note de service et l'état du classificateur de modération (WS4).

## Boutique (http://localhost:8000/shop)
Version « client » de Nova, sans la couche CTF : utile pour une démonstration grand public.
- Sélecteur **Vulnérable | Sécurisé** en haut à droite (nouvelle conversation à chaque changement).
- Bouton « Laisser un avis ».

## Structure
```
app/         serveur FastAPI (server.py), moteur CTF (ctf.py), orchestrateur du chat, interface (static/)
agent/       Nova Agent : boucle ReAct connectée au serveur MCP (agent.py)
mcp_server/  serveur MCP officiel (bibliothèque mcp) : outils et ressource de ShopNova
rag/         base ChromaDB : store.py, ingest.py, seed_reviews.py, docs/ (FAQ)
data/        seed.py (clients/commandes), memory_store.py, outbox.py, fichiers générés (.db, .json)
docs/        design doc, registre des vulnérabilités (privé, réservé WS1/WS5)
```
Réinitialiser la base RAG : supprimer `rag\store\` puis relancer `ingest.py` et `seed_reviews.py`.
Réinitialiser les clients/commandes : relancer `python data\seed.py` (écrase `data\shop.db`).
Épingler les versions exactes dans `app\requirements.txt` après une installation réussie (`pip freeze`).

## WS4 : le classificateur de modération
Aucune installation supplémentaire : `data/ws4_model.py` est pur Python, sans dépendance. Contrairement à WS2/WS3, ces 5 défis ne dépendent pas d'un LLM et sont donc **déterministes** (pas besoin de répéter 3 à 5 fois).

