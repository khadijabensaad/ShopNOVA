# WS4 · AI Security & Supply Chain

Extension de l'espace **RAG Attack Team** (onglet **Model Security (WS4)**). Elle raconte une seule histoire :

> attaquer un modèle IA → compromettre sa chaîne d'approvisionnement → vérifier son intégrité →
> sécuriser son utilisation (RAG) → détecter et prouver les attaques.

Aucun défi CTF n'a été renommé : B1 à B5 gardent leurs identifiants, leurs flags et leur comportement en mode vulnérable.

## 1. Adversarial ML (réutilise B1, B2, B3, B5)

| Attaque | Défi | Scénario | Composant | Contre-mesure (mode durci) |
|---|---|---|---|---|
| Evasion | B1 | RAG-S07 | Moderation Model | règle des marqueurs forts, `CTL-RAG-08` |
| Data Poisoning | B2 | RAG-S09 | Moderation Model | réentraînement verrouillé, `CTL-RAG-06` |
| Model Extraction | B3 | RAG-S08 | Moderation Model | score masqué, `CTL-RAG-05` |
| Membership Inference | B5 | RAG-S08 | Moderation Model | score masqué, `CTL-RAG-05` |

Les cartes de l'interface reprennent l'objectif, le principe (`learn` du défi), la contre-mesure (`fix` du défi)
et le **dernier résultat réellement enregistré** dans chaque mode (aucune valeur par défaut affichée comme résultat).

## 2. Scanner de fichiers de modèle (`data/model_security.py`)

Analyse **statique** : le fichier n'est jamais désérialisé avec Pickle et aucun code n'est exécuté.

| Contrôle | Règle |
|---|---|
| Extension | seule `.json` est acceptée ; `.pkl .pickle .pt .pth .joblib .bin .ckpt` et les autres formats (`.onnx`, `.h5`, `.gguf`…) sont refusés |
| Format réel | signature binaire détectée (Pickle, ZIP, GGUF, HDF5) : un Pickle renommé en `.json` est détecté |
| Pickle | opcodes lus avec `pickletools.genops` (sans exécution) ; références comme `posix.system` signalées |
| Taille | ≤ 64 Ko, ≤ 500 poids |
| Structure et champs | JSON valide, `bias` et `weights` obligatoires, champs inconnus refusés |
| Valeurs | nombres finis (NaN / Infinity refusés), `|poids|` ≤ 10, `|bias|` ≤ 10 |
| Empreinte | SHA-256 du fichier |
| Provenance | bloc `provenance` (fournisseur, source) attendu ; absence signalée en avertissement |

Verdict : **accepted** ou **rejected**. Chaque rapport est conservé comme preuve (`data/ws4_last_scan.json` et
Evidence Center). **Limite** : un scanner statique réduit le risque mais ne garantit pas l'absence de
comportement malveillant (un modèle aux poids « plausibles » peut rester piégé).

## 3. Signature et vérification avant activation

| Étape | Mécanisme |
|---|---|
| Empreinte | SHA-256 du fichier (intégrité seule : n'identifie pas l'auteur) |
| Signature | **Sigstore réel** via OpenSSF `model_signing` si installé et configuré ; sinon **démo locale Ed25519** clairement étiquetée « non Sigstore » |
| Métadonnées | algorithme, identité, émetteur, empreinte signée, date (`data/ws4_custom_model.sig.json`) |
| Vérification | intégrité + signature + **identité et émetteur attendus** ; les trois doivent réussir |
| Activation | en mode durci, refusée si la vérification échoue ; à l'usage, un fichier modifié après activation est ignoré (repli sur le modèle officiel) |

Le mode **démo locale** n'est jamais présenté comme une signature Sigstore : `mode: local-demo`,
`issuer: local-demo (non Sigstore)` et un avertissement accompagnent chaque enregistrement.

Clés : `data/keys/` (créé à l'exécution, permissions 0600) ou `SHOPNOVA_SIGNING_KEY` / `SHOPNOVA_KEYS_DIR`.
Ce dossier est exclu de Git (`.gitignore`) et de l'image Docker (`.dockerignore`). **Seul l'administrateur**
(éditeur de confiance, permission `model:sign`) peut signer ; la Team RAG importe, vérifie et active.

### Activer la vraie vérification Sigstore
Outil retenu : `model_signing` (projet OpenSSF *model-transparency*, bâti sur sigstore-python), conçu pour signer
des fichiers et dossiers de modèles. Cosign reste l'outil adapté aux images de conteneur ; il n'est pas nécessaire ici.
```bash
pip install model-signing
# signature par l'éditeur (hors du lab) : ouvre un flux OIDC, certificat éphémère, entrée dans Rekor
model_signing sign data/ws4_custom_model.json --signature data/ws4_custom_model.json.sig
# vérification manuelle équivalente à celle du lab
model_signing verify data/ws4_custom_model.json --signature data/ws4_custom_model.json.sig \
    --identity editeur@exemple.org --identity_provider https://accounts.google.com
# identité attendue par le lab (PowerShell)
$env:SHOPNOVA_SIGSTORE_IDENTITY = "editeur@exemple.org"
$env:SHOPNOVA_SIGSTORE_ISSUER   = "https://accounts.google.com"
```
Sigstore nécessite un accès réseau (Fulcio, Rekor) : le reste du lab fonctionne hors ligne.
Cette intégration n'a pas pu être exécutée dans l'environnement de développement (pas de réseau ni d'identité OIDC) ;
sans configuration, l'interface affiche « Sigstore : non installé / non configuré » et aucune vérification Sigstore
n'est déclarée réussie.

## 4. AI-BOM CycloneDX (`data/aibom.py`)

CycloneDX **1.7** (version courante de la spécification, publiée le 21 octobre 2025). Généré à partir de l'état
réel du projet : configuration Ollama (`/api/tags` interrogé, sinon « indisponible »), modèle officiel WS4
(empreinte canonique), documents `rag/docs` (SHA-256), bibliothèques installées (`importlib.metadata`).

- Composants : Qwen 2.5 3B, Nomic Embed Text, classificateur WS4 (`machine-learning-model`), base ChromaDB et FAQ
  (`data`), ollama, chromadb, mcp, onnxruntime, tokenizers, numpy, fastapi, uvicorn, pydantic, faker, cryptography.
- Aucune version inventée : un champ inconnu est signalé dans la propriété `shopnova:unknown-fields`.
- Le *digest* du manifeste Ollama est noté comme tel (propriété), pas comme empreinte des poids.
- Validation locale structurelle (références, dépendances, types, empreintes) ; validation officielle par le
  schéma CycloneDX avec `cyclonedx-python-lib[json-validation]` (exécutée en CI).

```bash
python data/aibom.py -o ai-bom.cdx.json            # génère + valide
python data/aibom.py --validate ai-bom.cdx.json --require-official
```
L'interface affiche l'**AI Supply Chain Inventory** et propose l'export JSON. Le contrôle `CTL-RAG-13` est validé
en direct par la génération et la validation de l'AI-BOM courant.

## 5. CI (`.github/workflows/model-security.yml`)
`permissions: contents: read`, aucun secret requis, aucun téléchargement de modèle lourd.
1. `scripts/model_scan.py` : repère les fichiers de modèle, vérifie extensions, structure, valeurs, intégrité et
   signatures présentes ; code de sortie 1 si une règle bloquante est violée.
2. Génération et validation officielle de l'AI-BOM.
3. Tests pytest (dont fixtures : modèle valide, modifié après signature, malformé, format interdit, poids anormaux, NaN).
4. Rapport du scanner et AI-BOM publiés comme artefacts.
Un job `sigstore-verify` optionnel s'exécute seulement si les variables `SIGSTORE_IDENTITY` et `SIGSTORE_ISSUER` sont définies.

## 6. Sécurité vectorielle (`rag/vector_security.py`)

| Attaque | Scénario | Ce qui est montré | Défense (mode durci) |
|---|---|---|---|
| Vector Poisoning | RAG-S13 | document écrit directement dans ChromaDB, son indexation, sa récupération, son effet sur le contexte | sceau de provenance HMAC à l'ingestion, vérifié à la récupération (`CTL-RAG-11`) |
| Retrieval Manipulation | RAG-S14 | requête, documents récupérés, distance, confiance, provenance, contexte final | sources officielles d'abord, filtrage des contenus tiers avec instruction ou contact externe, 1 extrait tiers max, isolation (`CTL-RAG-12`) |

L'**inspecteur de récupération** interroge la vraie base ChromaDB. Si ChromaDB ou le modèle d'embeddings ne
répondent pas, il affiche « indisponible » et les scénarios RAG-S13/S14 sont marqués **unavailable** : aucune
récupération n'est simulée. Le document de test injecté est supprimé après chaque exécution.

## 7. Blue Team

| Contrôle | Vérification réelle |
|---|---|
| CTL-RAG-09 Model File Validation | scénarios RAG-S10 / RAG-S12 en mode durci (rejet par le scanner) |
| CTL-RAG-07 Model Integrity Verification | RAG-S12 durci : fichier modifié après activation ignoré |
| CTL-RAG-10 Model Signature Verification | RAG-S10 / RAG-S12 durcis : activation refusée sans signature valide |
| CTL-RAG-13 AI-BOM Validation | génération + validation de l'AI-BOM à chaque consultation des contrôles |
| CTL-RAG-11 RAG Source Provenance | RAG-S13 durci (nécessite ChromaDB + Ollama) |
| CTL-RAG-12 Vector Retrieval Validation | RAG-S14 durci (nécessite ChromaDB + Ollama), statut « partiel » |

Détection : `DET-ML-02` (modèle rejeté), `DET-ML-03` (vérification échouée), `DET-RAG-02` (extrait sans
provenance valide), `DET-RAG-03` (premier extrait tiers avec instruction ou contact externe).
Un contrôle n'est marqué validé que par les exécutions en mode durci enregistrées (preuves hachées) ; un
finding ne passe à `VERIFIED` qu'après retest.

## Ce qui est réel, ce qui est pédagogique
| Réel | Démonstration pédagogique |
|---|---|
| scanner statique, SHA-256, Ed25519, vérification avant activation, AI-BOM, provenance HMAC, politique de récupération, preuves, détections, CI | signature « local-demo » (remplace Sigstore hors configuration) ; classificateur WS4 volontairement simple ; modèles Qwen/Nomic inventoriés mais non signés par le lab |
