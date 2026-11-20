// Attack History : toutes les exécutions visibles par le rôle (chaque équipe ne voit que les siennes).
import { api } from '../api.js';
import { h, icon, mount, badge } from '../ui.js';
import { setCrumbs } from '../main.js';
import { executionsTable, filterBar } from '../tables.js';

export async function render(root, { app }) {
  setCrumbs('Opérations', 'Attack History');
  const { executions } = await api.get('/executions?limit=1000');
  const table = executionsTable(executions, { pageSize: 15 });
  const { bar } = filterBar([
    { key: 'q', type: 'search', label: 'Rechercher (exécution, scénario, résumé)' },
    { key: 'team', type: 'select', label: 'Équipe', options: ['AGT', 'LLM', 'RAG'].filter((t) => app.can(`evidence:${t}`)).map((t) => [t, app.meta.teams[t].short]) },
    { key: 'mode', type: 'select', label: 'Mode', options: [['vulnerable', 'Vulnérable'], ['hardened', 'Durci']] },
    { key: 'outcome', type: 'select', label: 'Résultat', options: [['attack_succeeded', 'Réussie'], ['attack_blocked', 'Bloquée'], ['benign_ok', 'Légitime'], ['unavailable', 'Indisponible']] },
    { key: 'kind', type: 'select', label: 'Nature', options: [['test', 'test'], ['retest', 'retest'], ['chain', 'chain'], ['benign', 'benign'], ['adhoc', 'adhoc']] }],
  (f) => table.update(executions.filter((e) => (!f.q || `${e.id} ${e.scenario_id} ${e.summary}`.toLowerCase().includes(f.q)) && (!f.team || e.team === f.team)
    && (!f.mode || e.mode === f.mode) && (!f.outcome || e.outcome === f.outcome || (f.outcome === 'unavailable' && e.status === 'unavailable')) && (!f.kind || e.kind === f.kind))));
  mount(root,
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', { class: 'page-title' }, 'Historique des attaques'),
      h('p', { class: 'page-sub' }, 'Historique indépendant par équipe, consolidé pour la Blue Team et l\'audit. Cliquez une exécution pour ouvrir sa preuve.')),
    h('div', { class: 'head-actions' }, badge(`${executions.length} exécution(s)`, 'neutral'))),
    h('div', { class: 'card' }, bar, table));
}
