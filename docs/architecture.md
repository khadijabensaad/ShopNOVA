# Architecture de la plateforme v2

## Couches
```
                    ┌──────────────────── Plateforme SecOps (/, /api/secops) ─────────────────────┐
                    │ Command Center · 3 espaces d'attaque · Blue Team · Cross-Component · Registry │
                    │ Evidence · History · Monitoring · CTF · Reports · Settings                    │
                    └──────────────┬───────────────────────────────────────────────────────────────┘
                                   │ auth.py (RBAC)  engine.py (exécution, preuves, workflow)
                                   │ runners.py (attaques réelles)  detection.py (SOC)  metrics.py
          ┌────────────────────────┼────────────────────────────┬──────────────────────────┐
     orchestrator.py          guards.py                 agent.call_tool_raw()        ws4_model.py
  (preflight, contexte,   (ingestion RAG, note,       (session MCP stdio réelle)   (modération)
   prompt, sortie)         lecture de la base)               │
          │                        │                  mcp_server/server.py ── SQLite (Faker)
     Ollama (Qwen)            ChromaDB (nomic)
```
Le lab historique (`/api/chat`, `/api/review`, `/api/ctf/*`, `/api/mcp/call`…) est la **cible** : il reste sans
authentification par conception. La plateforme l'attaque à travers le même code (`guards.py`, orchestrateur,
serveur MCP), en passant le mode **explicitement** à chaque exécution (aucune dépendance au mode global).

Pas de microservice : un seul processus FastAPI, des modules Python séparés par responsabilité.

## Modèle de données (`data/secops.db`)
| Table | Contenu |
|---|---|
| `users`, `sessions` | comptes (PBKDF2), empreintes SHA-256 des jetons de session |
| `executions` | `EXE-000001` : scénario, équipe, composant, mode, nature (test/retest/benign/chain/adhoc), statut, résultat, détection, durée |
| `evidence` | `EVD-000001` : contenu JSON (secrets masqués), SHA-256, secrets détectés |
| `findings` | `AGT-001`, `LLM-001`, `RAG-001` : un par scénario, cycle de vie, références, équipes associées, incident |
| `finding_history` | toutes les transitions, avec auteur et note |
| `security_events` | alertes des règles `DET-*` |
| `incidents` | `XC-001` : chaîne multi-composants, équipe d'entrée, équipes associées |
| `audit_log` | connexions, exécutions, transitions, exports, administration |

## Cycle de vie
`OPEN → ANALYZED → MITIGATION_IN_PROGRESS → FIXED → RETEST_REQUIRED → VERIFIED`
- Transitions manuelles : Blue Team / admin. `VERIFIED` est **refusé** par l'API en transition manuelle.
- Retest : équipe responsable (ou admin), seulement en `RETEST_REQUIRED`, exécuté en mode durci.
  Attaque bloquée → `VERIFIED` ; attaque réussie → `MITIGATION_IN_PROGRESS` (retest « fail »).
- Régression : une attaque réussie en mode durci sur un finding `VERIFIED` le rouvre.

## Rôles (vérifiés côté serveur)
| Rôle | Espaces | Actions |
|---|---|---|
| Administrateur | tous | tout, gestion de la plateforme |
| AI Agent / LLM / RAG Attack Team | son espace, registre partagé (lecture) | exécuter, retester et éditer (description/impact) ses findings ; chaîne multi-composants |
| Blue Team | Defense Center, toutes les preuves, monitoring | triage, responsable, mitigation, transitions, export |
| Auditeur | lecture de tout, audit | export |

## Sécurité de la plateforme
PBKDF2-SHA256 (200 000 itérations), cookie `HttpOnly; SameSite=Strict`, en-tête anti-CSRF obligatoire sur les
écritures, limitation des tentatives de connexion, CSP stricte (`script-src 'self'`), `X-Frame-Options: DENY`,
`no-store` sur l'API, preuves hachées et secrets masqués, aucun `innerHTML` pour du contenu dynamique, journal
d'audit. Les erreurs internes restent dans la console du serveur.

## Interface
HTML/CSS/JS sans framework (choix justifié : le frontend existant n'utilisait pas React ; aucune étape de build).
- Jetons de design (`tokens.css`) : deux thèmes conçus séparément, un seul jeu de composants.
- Thème appliqué avant le premier rendu (`theme-init.js`), persistant, suit le système si demandé.
- Graphiques SVG dont les couleurs sont des variables CSS : ils suivent le thème sans être redessinés.
- 3D : moteur canvas maison (`scene3d.js`) — projection perspective, rotation, survol, clic, particules, ombres.
  Utilisé seulement pour l'architecture (Command Center), les pipelines des trois équipes et la chaîne d'attaque.
  Pause hors écran, `prefers-reduced-motion` respecté, réglage 3D haute/légère/désactivée, repli 2D. Aucun CDN
  requis (le lab fonctionne hors-ligne ; seules les polices Google sont optionnelles).
- Tableaux, formulaires et résultats de sécurité restent en 2D.

## WS4 · AI Security & Supply Chain
```
 Interface : onglet « Model Security (WS4) » (pages/ws4.js, espace RAG)
        │  /api/secops/ws4/*  (api.py : RBAC, audit, preuves via _adhoc)
        ├── data/model_security.py   scanner statique · SHA-256 · signature Ed25519 (local-demo) · Sigstore (model_signing)
        ├── data/ws4_model.py         upload → scan → (inactif) → signature → vérification → activation ; repli si altéré
        ├── data/aibom.py             AI-BOM CycloneDX 1.7 depuis l'état réel (Ollama, rag/docs, paquets installés)
        └── rag/vector_security.py    sceau de provenance HMAC · politique de récupération (orchestrator.build_context)
 Blue Team : scénarios RAG-S12..S14 (runners.py), contrôles CTL-RAG-07, 09..13 (catalog.py), règles DET-ML-02/03,
             DET-RAG-02/03 (detection.py), CTL-RAG-13 validé en direct dans /controls.
 CI : scripts/model_scan.py + .github/workflows/model-security.yml
```
| Route | Permission | Rôle |
|---|---|---|
| `GET /ws4/overview` | `evidence:RAG` | cartes Adversarial ML (B1–B5) + état de la chaîne d'approvisionnement |
| `POST /ws4/model/scan` | `run:RAG` | import + analyse (texte ou base64, ≤ 256 Ko) ; preuve `model_scan` |
| `POST /ws4/model/sign` | `model:sign` (administrateur) | signature par l'éditeur de confiance |
| `POST /ws4/model/verify` | `evidence:RAG` | intégrité, signature, identité ; preuve `model_verification` |
| `POST /ws4/model/activate` | `run:RAG` | activation (mode durci : vérification obligatoire) |
| `POST /ws4/model/reset` | `run:RAG` | retour au modèle officiel |
| `GET /ws4/aibom`, `/ws4/aibom/export` | `evidence:RAG` | inventaire, validation, export JSON |
| `POST /ws4/rag/retrieve` | `run:RAG` | récupération ChromaDB réelle + politique ; 503 « indisponible » sinon |

Séparation : logique métier dans `data/` et `rag/`, API dans `app/secops/api.py`, interface dans `pages/ws4.js`.
Clés locales dans `data/keys/` (0600), exclues de Git et de l'image Docker. Dépendance ajoutée : `cryptography`.
