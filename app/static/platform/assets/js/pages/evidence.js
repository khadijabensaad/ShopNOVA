// Evidence Center : preuves hachées (SHA-256) produites par chaque exécution, vérification d'intégrité à l'ouverture.
import { api } from '../api.js';
import { h, icon, mount, badge } from '../ui.js';
import { setCrumbs } from '../main.js';
import { openEvidence } from '../finding.js';
import { evidenceTable, filterBar } from '../tables.js';

export async function render(root, { app, params }) {
  setCrumbs('Opérations', 'Evidence Center');
  const { evidence } = await api.get('/evidence');
  const table = evidenceTable(evidence, { pageSize: 14 });
  const { bar } = filterBar([
    { key: 'q', type: 'search', label: 'Rechercher (preuve, finding, scénario)' },
    { key: 'team', type: 'select', label: 'Équipe', options: ['AGT', 'LLM', 'RAG'].filter((t) => app.can(`evidence:${t}`)).map((t) => [t, app.meta.teams[t].short]) },
    { key: 'mode', type: 'select', label: 'Mode', options: [['vulnerable', 'Vulnérable'], ['hardened', 'Durci']] },
    { key: 'kind', type: 'select', label: 'Nature', options: [['test', 'test'], ['retest', 'retest'], ['benign', 'benign'], ['chain', 'chain'], ['adhoc', 'adhoc']] },
    { key: 'flags', type: 'select', label: 'Secrets', options: [['yes', 'Avec secret détecté'], ['no', 'Sans secret']] }],
  (f) => table.update(evidence.filter((e) => (!f.q || `${e.id} ${e.finding_id} ${e.scenario_id}`.toLowerCase().includes(f.q)) && (!f.team || e.team === f.team)
    && (!f.mode || e.mode === f.mode) && (!f.kind || e.kind === f.kind) && (!f.flags || (f.flags === 'yes') === (e.flags_detected.length > 0)))));
  mount(root,
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', { class: 'page-title' }, 'Preuves'),
      h('p', { class: 'page-sub' }, 'Format commun aux trois équipes : requête, réponse, décisions des contrôles, détections. Chaque preuve est hachée à sa création ; l\'intégrité est revérifiée à l\'ouverture. Les secrets sont masqués.')),
    h('div', { class: 'head-actions' }, badge(`${evidence.length} preuve(s) visibles pour votre rôle`, 'neutral', 'lock'))),
    h('div', { class: 'card' }, bar, table));
  if (params.get('e')) openEvidence(params.get('e'));
}
