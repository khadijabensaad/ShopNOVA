# ShopNOVA AI Security Lab — IA as a Target (v2 · WS4 Supply Chain)

> Laboratoire pédagogique **volontairement vulnérable**. Données fictives, actions simulées, exécution locale
> uniquement (ports liés à `127.0.0.1`). Ne jamais l'exposer sur Internet.

**Build · Threat model · Attack · Detect · Defend · Remediate · Retest · Validate**

ShopNOVA est une boutique fictive dotée d'une assistante IA, **Nova** (LLM Qwen via Ollama, RAG ChromaDB +
Nomic Embed Text, agent ReAct connecté à un serveur MCP). La v2 ajoute une **plateforme SecOps** organisée autour de :

| | Équipe | Périmètre exclusif |
|---|---|---|
| TEAM 01 | **AI Agent Attack Team** | agent ReAct, outils MCP, permissions, mémoire, actions |
| TEAM 02 | **LLM Attack Team** | prompts, instructions système, contexte, sorties, consommation |
| TEAM 03 | **RAG Attack Team** | ingestion documentaire, modération, embeddings, récupération, provenance |
| — | **Shared Blue Team** | triage, mitigation, contrôles, audit, validation par retest |

Les trois équipes ont des espaces, scénarios, historiques, preuves et métriques **séparés**, et partagent un
**registre unique des vulnérabilités**, la surveillance, l'Evidence Center, l'analyse multi-composants et les rapports.

---

## Installation (Windows, PowerShell)
```powershell
ollama pull qwen2.5:3b
ollama pull nomic-embed-text
cd ShopNOVA_Lab
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r app\requirements.txt
python setup_flags.py          # crée .env : flags aléatoires + mot de passe de la plateforme (affiché)
python data\seed.py            # clients et commandes fictifs
python rag\ingest.py           # indexe la FAQ officielle
python rag\seed_reviews.py     # avis de départ
python check_lab.py            # diagnostic : tout doit afficher OK
python app\server.py           # http://localhost:8000
```
Linux/macOS : mêmes commandes avec `/`. Docker : `docker compose up --build` (voir les commentaires de
`docker-compose.yml` pour télécharger les modèles dans le conteneur Ollama).

### Comptes de la plateforme
`admin`, `agent`, `llm`, `rag`, `blue`, `auditor` — mot de passe : `PLATFORM_PASSWORD` du fichier `.env`.
Sans cette variable, le mot de passe de démonstration `ShopNova!2026` est utilisé et un avertissement s'affiche.
Pour changer de mot de passe : modifier `.env` puis supprimer `data/secops.db` (les comptes sont recréés).

## Interfaces
| Adresse | Rôle |
|---|---|
| `http://localhost:8000/` | **Plateforme SecOps** (authentifiée) : Command Center, 3 espaces d'attaque, Blue Team, registre… |
| `http://localhost:8000/ctf` | Interface CTF d'origine (inchangée) |
| `http://localhost:8000/shop` | Boutique « client » de Nova (inchangée) |

## Démonstration en 5 minutes (jury)
1. Connexion `admin` → **Command Center** vide (aucun chiffre inventé) → **Campagne de référence (3 équipes)**.
2. Les KPI, la scène 3D, les cartes d'équipe et « Which AI component is the most vulnerable? » se remplissent.
3. **AI Agent Attack Team → Tool Call Inspector** : appeler `get_customer(7)` en mode vulnérable puis durci.
4. **Cross-Component** : exécuter la chaîne RAG → LLM → Agent → MCP (vulnérable : exfiltration confirmée ;
   durci : bloquée par `CTL-AGT-05`, avec les points de détection).
5. Connexion `blue` → **Defense Center** : faire passer `AGT-001` jusqu'à `RETEST_REQUIRED`.
6. Connexion `agent` → lancer le **retest** : `AGT-001` devient `VERIFIED`. Recommencer avec `AGT-005` : le retest
   **échoue** (correctif contournable `manager_override`) — le finding repart en `MITIGATION_IN_PROGRESS`.
7. **Reports** → export HTML du rapport (Blue Team / auditeur).

### Démonstration WS4 · AI Security & Supply Chain (RAG → onglet **Model Security (WS4)**)
1. **Adversarial ML** : une carte par attaque (Evasion B1, Data Poisoning B2, Model Extraction B3, Membership
   Inference B5) ; « Démontrer » puis « Rejouer (durci) » exécutent les scénarios réels.
2. **Model Supply Chain** (connexion `rag`) : cible « Durci » → **Importer et analyser** (rapport du scanner) →
   **Activer** : refusé, modèle non signé.
3. Connexion `admin` → **Signer** (démo locale Ed25519, étiquetée « non Sigstore »).
4. Connexion `rag` → **Vérifier** puis **Activer** : intégrité, signature et identité vérifiées.
5. Importer `tests/fixtures/models/forbidden_format.pkl` : rejeté sans être chargé, détection `DET-ML-02`.
6. **AI Supply Chain Inventory** : AI-BOM CycloneDX 1.7, champs inconnus signalés, export JSON.
7. **RAG & Vector Security** : inspecteur de récupération (distance, confiance, provenance, décision, contexte
   final) et scénarios RAG-S13 / RAG-S14 ; « indisponible » si ChromaDB ou Ollama ne répondent pas.
Détails, limites et configuration Sigstore : [`docs/ws4-supply-chain.md`](docs/ws4-supply-chain.md).

## Ce qui est réel, ce qui ne l'est pas
- Chaque scénario exécute une **vraie opération** : appel d'outil via une vraie session MCP, contrôles réels de
  l'orchestrateur, passerelle d'ingestion, classificateur, et le modèle Qwen pour les scénarios « modèle réel ».
- Si Ollama est arrêté, ces derniers sont marqués **indisponibles** : aucun résultat n'est simulé.
- Dans la chaîne multi-composants, les étapes « interprétation LLM » et « décision de l'agent » sont affichées
  comme **chemin simulé** (probabiliste) ; l'appel MCP final est réellement exécuté. Les scénarios AGT-S10 et
  RAG-S11 vérifient ces étapes en conditions réelles avec le modèle.
- WS4 : le scanner, les empreintes, la signature Ed25519, la vérification avant activation, l'AI-BOM et le sceau
  de provenance RAG sont réels. La signature « local-demo » **n'est pas** une signature Sigstore et l'affiche ;
  la vérification Sigstore réelle (`model_signing`) n'est active qu'une fois installée et configurée.
- Toutes les métriques sont calculées à partir des exécutions enregistrées (`data/secops.db`). Leurs définitions
  sont affichées dans l'interface et dans `app/secops/metrics.py`.

## Tests
```bash
python -m pytest -q tests                 # 48 tests : auth, RBAC, moteur, workflow, chaîne, CTF, WS4 supply chain
python tests/run_dev_server.py 8765       # serveur de test
python tests/e2e/ui_tour.py               # parcours Playwright : toutes les pages, 2 thèmes, mobile, workflow
python tests/e2e/ws4_tour.py              # parcours Playwright de l'onglet Model Security (WS4)
python scripts/model_scan.py              # contrôle des fichiers de modèle (utilisé par la CI)
python data/aibom.py -o ai-bom.cdx.json   # génère et valide l'AI-BOM CycloneDX
```
La CI GitHub Actions (`.github/workflows/model-security.yml`, lecture seule, sans secret) exécute le scanner,
l'AI-BOM avec validation officielle du schéma et les tests.

`tests/shim/` contient un sous-ensemble minimal de l'API FastAPI, utilisé **uniquement** si FastAPI n'est pas
installé (CI hors-ligne). En usage normal, la vraie bibliothèque FastAPI est utilisée.

## Structure
```
app/            server.py (routes), orchestrator.py (LLM), guards.py (contrôles web/RAG), ctf.py (moteur CTF)
app/secops/     plateforme : auth.py (RBAC), catalog.py (équipes, scénarios, contrôles), runners.py (attaques),
                engine.py (exécution, preuves, workflow), detection.py (SOC), metrics.py, reports.py, api.py
app/static/platform/  interface (HTML/CSS/JS sans framework, 3D canvas maison, thèmes clair/sombre)
agent/  mcp_server/  rag/  data/      composants IA du lab (inchangés dans leur rôle)
data/model_security.py  data/aibom.py  rag/vector_security.py   WS4 : scanner, signature, AI-BOM, provenance RAG
scripts/model_scan.py   .github/workflows/model-security.yml     contrôle CI des modèles
docs/           audit.md, architecture.md, security-mapping.md, vuln-register.md (privé), lab-design.md,
                ws4-supply-chain.md
tests/          tests pytest, shim de test, parcours e2e
```

## Réinitialisations
- CTF : bouton **Réinitialiser** (page CTF) — score, avis, mémoire, boîte d'envoi, note, classificateur.
- Plateforme : **Settings → Effacer l'activité** (admin) — exécutions, preuves, findings, événements.
- Base RAG : supprimer `rag/store/` puis relancer `ingest.py` et `seed_reviews.py`.
- Modèle WS4 : bouton **Rétablir l'officiel** (onglet Model Security) ; les clés locales sont dans `data/keys/`
  (jamais versionnées ; les supprimer en génère de nouvelles et invalide les anciennes signatures).
