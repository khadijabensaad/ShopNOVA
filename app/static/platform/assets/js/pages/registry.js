// Registre des vulnérabilités partagé : un seul registre pour les trois équipes et la Blue Team.
import { api } from '../api.js';
import { h, icon, mount, STATUS_LABEL, badge } from '../ui.js';
import { setCrumbs } from '../main.js';
import { openFinding } from '../finding.js';
import { findingsTable, filterBar } from '../tables.js';

export async function render(root, { app, params }) {
  setCrumbs('Opérations', 'Vulnerability Registry');
  const { findings } = await api.get('/findings');
  const reload = () => render(root, { app, params });
  const comps = [...new Set(findings.map((f) => f.component))].sort();
  const table = findingsTable(findings, { onChange: reload, pageSize: 12 });
  const { bar } = filterBar([
    { key: 'q', type: 'search', label: 'Rechercher (ID, titre, catégorie)' },
    { key: 'team', type: 'select', label: 'Équipe', options: ['AGT', 'LLM', 'RAG'].map((t) => [t, app.meta.teams[t].name]) },
    { key: 'severity', type: 'select', label: 'Sévérité', options: [['critical', 'Critique'], ['high', 'Élevée'], ['medium', 'Moyenne'], ['low', 'Faible']] },
    { key: 'status', type: 'select', label: 'Statut', options: app.meta.statuses.map((s) => [s, STATUS_LABEL[s]]) },
    { key: 'component', type: 'select', label: 'Composant', options: comps.map((c) => [c, c]) }],
  (f) => table.update(findings.filter((x) => (!f.q || `${x.id} ${x.title} ${x.category}`.toLowerCase().includes(f.q)) && (!f.team || x.team === f.team)
    && (!f.severity || x.severity === f.severity) && (!f.status || x.status === f.status) && (!f.component || x.component === f.component))));
  mount(root,
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', { class: 'page-title' }, 'Registre des vulnérabilités'),
      h('p', { class: 'page-sub' }, 'Identifiants AGT-xxx, LLM-xxx et RAG-xxx. Un finding par scénario (pas de doublon) ; les défis CTF historiques restent référencés (A1…E4, V01…V20).')),
    h('div', { class: 'head-actions' }, badge(`${findings.length} finding(s)`, 'b-primary'))),
    h('div', { class: 'card' }, bar, table));
  if (params.get('f')) openFinding(params.get('f'), reload);
}
