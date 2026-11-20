# Correspondance avec les référentiels

Évaluation **alignée sur une sélection d'exigences** — ce n'est ni une certification ISO ni un audit de conformité.
Identifiants MITRE ATLAS à revérifier dans la version courante d'ATLAS avant publication.

## Scénarios → OWASP Top 10 for LLM Applications (2025) et MITRE ATLAS
| Équipe | Scénarios | OWASP LLM | ATLAS (technique) |
|---|---|---|---|
| AGT | S01, S02, S03, S09 | LLM06 Excessive Agency, LLM02 | AML.T0053 LLM Plugin Compromise, AML.T0057 LLM Data Leakage |
| AGT | S04, S05, S11 | LLM06 Excessive Agency | — |
| AGT | S06, S10 | LLM06, LLM01 | AML.T0051.001 Indirect Prompt Injection |
| AGT | S07 | LLM04 Data and Model Poisoning | AML.T0080 AI Agent Context Poisoning |
| AGT | S08 | LLM01 Prompt Injection | AML.T0051.001 |
| LLM | S01, S07 | LLM07 System Prompt Leakage | AML.T0056 Extract LLM System Prompt |
| LLM | S02 | LLM02 Sensitive Information Disclosure | — |
| LLM | S03 | LLM10 Unbounded Consumption | AML.T0029 Denial of ML Service, AML.T0034 Cost Harvesting |
| LLM | S04, S05, S06, S09 | LLM01 Prompt Injection | AML.T0051.000 Direct, AML.T0054 LLM Jailbreak |
| LLM | S08 | LLM05 Improper Output Handling | — |
| RAG | S01, S03, S11, XC-S01 | LLM01, LLM04 | AML.T0070 RAG Poisoning, AML.T0051.001 |
| RAG | S02 | LLM08 Vector and Embedding Weaknesses | — |
| RAG | S04 | LLM09 Misinformation | — |
| RAG | S07 | LLM04 | AML.T0043 Craft Adversarial Data |
| RAG | S08 | LLM02 | AML.T0024 Exfiltration via AI Inference API |
| RAG | S09 | LLM04 | AML.T0020 Poison Training Data |
| RAG | S10 | LLM03 Supply Chain | AML.T0010 ML Supply Chain Compromise |

## Contrôles Blue Team → NIST AI RMF et ISO/IEC 42001
| Contrôle | NIST AI RMF (fonction) | Thème ISO/IEC 42001 / 27001 |
|---|---|---|
| CTL-AGT-01/05, CTL-RAG-02 (autorisation, liste blanche, lecture authentifiée) | MANAGE | Contrôle d'accès (27001 A.5.15) |
| CTL-AGT-04 approbation humaine (planifié) | GOVERN / MANAGE | Supervision humaine des systèmes d'IA (42001) |
| CTL-AGT-06, CTL-RAG-06/07 (intégrité mémoire, réentraînement, modèle) | MANAGE | Qualité et provenance des données, cycle de vie du système d'IA |
| CTL-LLM-01/02 (secrets, DLP) | MANAGE | Protection de l'information (27001 A.8.12) |
| CTL-LLM-03 (limites) | MANAGE | Gestion de capacité (27001 A.8.6) |
| CTL-RAG-03/04 (isolation, provenance) | MAP / MANAGE | Transparence et traçabilité |
| Règles DET-* et journal d'audit | MEASURE | Journalisation et surveillance (27001 A.8.15/A.8.16) |
| Retest obligatoire avant VERIFIED | MEASURE | Vérification de l'efficacité des mesures |
| Registre partagé et rapports | GOVERN | Gestion des risques liés à l'IA |
