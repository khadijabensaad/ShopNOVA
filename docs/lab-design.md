# Lab Design Document - ShopNova Assist

**Projet :** IA as a Target - **Pôle :** WS1 (fondamentaux et construction du lab)
**Version du document :** 0.1 - **Statut :** brouillon à valider avec le groupe

> ⚠️ Ce lab est **volontairement vulnérable**. Il tourne uniquement en local, n'est jamais exposé sur Internet et ne contient aucune donnée réelle.

---

## 1. Objectif

Fournir au groupe une **cible unique, locale et reproductible** sur laquelle les quatre autres pôles peuvent travailler :

| Pôle | Ce qu'il fait sur le lab |
|---|---|
| WS2 - Red Team | Prompt injection, jailbreaks, fuite du prompt système |
| WS3 - Agents et MCP | Excessive agency, tool poisoning, permissions excessives |
| WS4 - Données, modèle, supply chain | Empoisonnement du RAG, modèle non vérifié |
| WS5 - Défense, détection, gouvernance | Modèle de menaces, durcissement, détection, incident |

Le lab doit permettre de mesurer l'efficacité des défenses : même attaque **avant** (branche `vulnerable`) et **après** (branche `hardened`).

## 2. Scénario

**ShopNova** est une boutique en ligne fictive. **ShopNova Assist** est son assistant de support client : il répond sur les commandes, retours et livraisons, consulte une base de connaissances (FAQ, politiques) et, à partir de la v0.2, agit via des outils (consulter une commande, rembourser).

Choix justifié : les conséquences d'une attaque (remboursement frauduleux, fuite d'une fiche client) sont faciles à comprendre et à démontrer devant le jury.

## 3. Architecture

```
Utilisateur / Attaquant
        │
        ▼
 Interface (FastAPI + page web)
        │
        ▼
 Orchestrateur (Python) ── SECURE_MODE on/off
   │        │         │
   ▼        ▼         ▼
 Ollama   RAG       Serveur MCP (v0.2)
 (LLM)   (Chroma)        │
                         ▼
                  SQLite (données Faker)
```

Chaque flèche est une **frontière de confiance** (entrée utilisateur → modèle, documents → modèle, modèle → outils, outils → données). WS5 s'appuie sur ce schéma pour le modèle de menaces.

## 4. Composants et choix techniques

| Composant | Choix | Raison |
|---|---|---|
| Modèle | Ollama + petit modèle (qwen2.5:3b retenu pour le développement) | Local, gratuit, sans GPU ; plus facile à manipuler |
| Embeddings | Modèle d'embeddings servi par Ollama | Aucune API externe |
| Interface | FastAPI + page web | Rapide, onglets (Chat / Admin documents) |
| RAG | ChromaDB (FAQ et avis clients) | Simple, persistant |
| Agent | Boucle ReAct maison (inspirée de DVLA) | Contrôle total des failles |
| MCP | Petit serveur avec le SDK MCP Python (inspiré de DVMCP) | S'intègre au scénario |
| Données | Faker (graine fixe) + SQLite | Fausses données reproductibles |
| Déploiement | Docker Compose, ports liés à `127.0.0.1` | Une commande, isolé |

## 5. Registre des vulnérabilités (version publique, sans emplacements ni secrets)

| ID | Couche | Vulnérabilité | Famille de risque | Pôle |
|---|---|---|---|---|
| V01 | Chat | Secrets dans le prompt système | Fuite du prompt système | WS2 |
| V02 | Chat | Aucun filtrage des entrées | Injection de prompt | WS2 |
| V03 | Chat | Aucun contrôle des sorties | Divulgation d'informations sensibles | WS2 |
| V04 | Interface | HTML de la réponse interprété | Traitement non sûr des sorties | WS2 |
| V05 | Avis clients | Publication sans modération | Empoisonnement de la base | WS4 |
| V06 | Avis clients | Instructions cachées reprises par l'assistante | Injection indirecte | WS2/WS4 |
| V07 | API | Historique et rôles fournis par le client | Injection de prompt | WS2 |
| V08 | API | Aucune limite de taille, de sortie ni de débit | Consommation non bornée | WS2 |
| V09 | Chat | Politiques commerciales inventées | Désinformation | WS2 |
| V10 | API | Erreurs techniques renvoyées au client | Fuite d'informations | WS2 |
| V11 | API | Liste des avis sans authentification | Contrôle d'accès | WS2/WS4 |
| V12 | Agent/MCP | `get_customer` sans contrôle d'accès | Divulgation d'informations sensibles | WS3 |
| V13 | Agent/MCP | `refund` sans vérification de montant | Agentivité excessive | WS3 |
| V14 | Agent/MCP | Note de commande suivie comme une instruction | Injection indirecte | WS3 |
| V15 | Agent/MCP | Mémoire client sans validation | Empoisonnement de mémoire | WS3 |
| V16 | Agent/MCP | Note de service modifiable sans authentification | Empoisonnement de ressource MCP | WS3 |
| V17 | Agent/MCP | Correctif de remboursement contournable par mot-clé | Contournement de défenses | WS3/WS5 |
| V18 | Classificateur (WS4) | Score brut exposé (extraction, inférence d'appartenance) | Extraction de modèle | WS4 |
| V19 | Classificateur (WS4) | Réentraînement sans contrôle (boucle de rétroaction) | Empoisonnement du modèle | WS4 |
| V20 | Classificateur (WS4) | Import de modèle sans vérification d'intégrité | Chaîne d'approvisionnement | WS4 |

Les emplacements et les secrets sont dans `vuln-register.md` (privé). La numérotation OWASP est à compléter avec l'édition retenue.

## 6. Plateforme CTF

Les vulnérabilités ci-dessus sont rejouées comme des défis notés (score, indices, flags), accessibles sur la page d'accueil du lab. WS2 couvre le chat et le RAG ; WS3 couvre l'agent et le serveur MCP (protocole officiel, bibliothèque `mcp`). WS4 couvre un petit classificateur de modération (évasion, empoisonnement, extraction, chaîne d'approvisionnement, inférence d'appartenance), déterministe et sans LLM. WS5 couvre le durcissement d'un filtre (rappel/faux positifs), la détection d'une attaque dans un journal, un playbook de réponse à incident et une question de gouvernance (EU AI Act) — déterministe lui aussi, sans LLM ni état persistant.

## 7. Versions et planning

| Version | Contenu | Échéance indicative |
|---|---|---|
| Design | Ce document, schéma, Ollama fonctionnel sur chaque poste | Semaines 1-2 |
| **v0.1** | Chatbot + prompt système vulnérable + interface (V01-V04) | Semaine 3 |
| **v0.2** | RAG + agent + serveur MCP + données Faker (V05-V12) | Semaine 5 (avant la présentation Red Team) |
| **v0.3** | Branche `hardened` : filtres, moindres privilèges, validation humaine (avec WS5) | Semaines 6-7 |
| Gel | Version de référence pour la démo finale | Semaine 9 |

## 8. Mode vulnérable / sécurisé

Variable d'environnement `SECURE_MODE` :
- `false` : lab vulnérable (par défaut).
- `true` : protections activées (v0.1 : filtre d'entrée basique, secret retiré du prompt, masquage des flags en sortie, HTML échappé).

Objectif : lancer le **même jeu d'attaques** dans les deux modes et comparer les taux de réussite.

## 9. Isolation et éthique

- Ports liés à `127.0.0.1`, aucun service exposé.
- Aucune donnée réelle : tout vient de Faker.
- Attaques uniquement sur ce lab ou des plateformes d'entraînement autorisées.
- Charte éthique signée par les 10 membres (cf. livrables du projet).
- Aucun contenu réellement dangereux dans les tests (les jailbreaks visent des comportements fictifs du scénario).

## 10. Critères d'acceptation

- [ ] `docker compose up` lance le lab sur un poste vierge en moins de 15 minutes (hors téléchargement du modèle).
- [ ] Chaque membre du groupe peut lancer le lab et discuter avec le chatbot.
- [ ] Chaque vulnérabilité de la version livrée est exploitable et son flag est récupérable.
- [ ] La branche `hardened` bloque (ou réduit nettement) les attaques de référence.
- [ ] README et guide d'installation à jour.

## 11. Risques et parades

| Risque | Parade |
|---|---|
| Machines peu puissantes | Modèle de 3 Md de paramètres, tests du modèle dès la semaine 1 |
| Le modèle gère mal les appels d'outils | Tester le function calling tôt ; plan B : un autre modèle (famille Qwen) |
| Versions différentes d'un poste à l'autre | Versions épinglées dans le README, une seule image Docker de référence |
| Lab livré trop tard pour les attaquants | v0.1 volontairement simple, livrée en semaine 3 |
| Dérive du périmètre | Une vulnérabilité = une ligne du registre ; rien d'autre sans validation |

## 12. Interfaces avec les autres pôles

- **WS2 / WS3** : retours sur ce qui manque ; demandes de nouvelles failles via une issue Git.
- **WS4** : accès à la base vectorielle et au chargement du modèle.
- **WS5** : reçoit ce document pour le modèle de menaces, puis durcit la branche `hardened`.
