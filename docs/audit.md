# Audit du dépôt existant (v1) et corrections apportées (v2)

Périmètre lu : README, `app/` (server, config, orchestrator, ctf, static/index.html, static/ctf.html),
`agent/agent.py`, `mcp_server/server.py`, `rag/`, `data/`, `docs/`, `docker-compose.yml`, `setup_flags.py`,
`check_lab.py`. Les vulnérabilités **volontaires** du lab (V01–V20, A6) sont documentées dans `vuln-register.md` ;
elles ne sont pas des défauts et restent intactes en mode vulnérable.

## 1. Architecture existante
FastAPI (`server.py`) sert deux pages statiques et l'API. L'orchestrateur assemble prompt système + contexte RAG
(ChromaDB, embeddings Ollama) et appelle Qwen. L'agent ReAct lance le serveur MCP officiel en sous-processus
(stdio) à chaque appel. Les données fictives sont dans SQLite (Faker). Le moteur CTF (23 défis, WS2–WS5) évalue
des conditions de réussite et délivre des flags dérivés ou canaris. Un mode global `config.state["secure"]`
bascule entre comportement vulnérable et durci.

## 2. Constats techniques

| ID | Fichier / fonction | Constat | Sévérité | Impact | Correction (v2) | Test de validation |
|---|---|---|---|---|---|---|
| AUD-01 | `app/Dockerfile`, `docker-compose.yml` | Contexte de build = `app/` : `agent/`, `rag/`, `data/`, `mcp_server/` absents de l'image | Élevée | Agent, RAG et CTF WS3 inutilisables dans Docker | Contexte = racine, `dockerfile: app/Dockerfile`, seed au build, `.dockerignore` | `docker compose build` puis `/api/secops/health` |
| AUD-02 | `server.py` (imports) | `import ws4_model` ne marche que parce que `ctf.py` a modifié `sys.path` avant | Faible | Casse au moindre réordonnancement | Chemins explicites en tête de `server.py` | `test_pages_and_csp` |
| AUD-03 | `config.state` | Mode global mutable partagé par toutes les requêtes ; chaque défi le bascule | Moyenne | Résultats non reproductibles si plusieurs onglets/joueurs | Les fonctions de l'orchestrateur acceptent `secure=` explicite ; la plateforme n'utilise jamais l'état global | `test_orchestrator_steps` |
| AUD-04 | `orchestrator.py`, `agent.py` | `import ollama` au chargement : le serveur ne démarre pas sans la bibliothèque | Faible | Plateforme indisponible pour une dépendance optionnelle | Import paresseux + état « indisponible » explicite | `test_llm_scenarios_report_unavailable_without_model` |
| AUD-05 | `orchestrator.stream` | Contrôles d'entrée, construction du prompt et sortie mêlés dans un seul générateur | Moyenne | Impossible de tester chaque contrôle isolément | Découpage `preflight / retrieve / format_context / assemble_system_prompt / postprocess`, comportement identique | `test_orchestrator_steps` |
| AUD-06 | `data/memory_store.remember` (mode sécurisé) | Le « correctif » tronque seulement à 60 caractères | Élevée | Empoisonnement de mémoire toujours possible en mode durci | Validation par schéma (clés et valeurs énumérées) | `AGT-S07` durci = bloqué |
| AUD-07 | `data/ws4_model.classify` (mode sécurisé) | Le mode durci masque le score mais reste vulnérable à la dilution | Moyenne | Évasion de la modération en mode durci | Règle des marqueurs forts (poids officiel ≥ 3) | `RAG-S07` durci = bloqué |
| AUD-08 | `orchestrator.build_context` | Les extraits perdent source et niveau de confiance | Moyenne | Aucune traçabilité des affirmations du modèle | Provenance conservée en mode durci (`search_with_meta`) | `RAG-S04` durci = bloqué |
| AUD-09 | Interface | Aucune authentification ni séparation des rôles pour l'administration du lab | Élevée | Pas de traçabilité, pas de séparation des équipes | Plateforme `/api/secops` : PBKDF2, sessions HttpOnly/SameSite, CSRF, RBAC serveur, audit | `test_auth_rbac.py` |
| AUD-10 | `/api/mode` | Bascule globale sans authentification | Info | Conservée : nécessaire à l'interface CTF d'origine | Documenté ; la plateforme n'en dépend pas | — |
| AUD-11 | Dépôt | Aucun test automatisé | Moyenne | Régressions invisibles | 24 tests pytest + parcours Playwright | `pytest -q tests` |
| AUD-12 | `data/seed.py` | Dépendance stricte à Faker | Faible | Environnements hors-ligne bloqués | Repli déterministe sans dépendance | seed en CI |
| AUD-13 | README | « cinq pôles (WS2, WS3, WS4, WS5) », dossier `NOVASHOP_complet` | Info | Confusion à l'installation | README réécrit | — |
| AUD-14 | Interface v1 | Thème unique, styles en ligne, pas d'état vide ni d'accessibilité clavier | Moyenne | Démonstration peu professionnelle | Design system à jetons, clair/sombre, a11y, états vides | parcours e2e |

## 3. Contrôles existants (mode sécurisé) conservés
Prompt sans secret, masquage des `FLAG{}`, limites 800 caractères / 300 tokens, filtre FR/EN, nettoyage de
l'historique, modération des avis, liste des avis refusée, isolation du contexte, contrôle d'appartenance des outils
MCP, plafond de remboursement (contournable, V17, conservé pour A7), liste blanche e-mail, note non modifiable,
classificateur sans score / sans réentraînement / modèle vérifié par hachage.

## 4. Limites assumées (risque résiduel documenté)
- Le filtre d'injection par mots-clés reste contournable (LLM-S06, RAG-S01) : démonstration voulue.
- Pas d'approbation humaine des actions sensibles ni d'authentification des clients MCP (CTL-AGT-02/04 planifiés).
- Pas de quota de débit sur `/api/chat` (V08) ; la plateforme limite seulement les tentatives de connexion.
- Base RAG mono-locataire : l'isolation inter-utilisateurs n'est pas testable en l'état.
