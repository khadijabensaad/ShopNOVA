// Monitoring : flux des événements de sécurité (règles de détection appliquées à chaque exécution).
import { api, qs } from '../api.js';
import { h, icon, mount, card, badge, teamPill, fmtTime, dataTable, SEV } from '../ui.js';
import { bars, legend } from '../charts.js';
import { setCrumbs, sevColor } from '../main.js';
import { openEvidence } from '../finding.js';

let auto = true, timer = null, filters = { team: '', severity: '' };

export async function render(root, { app }) {
  setCrumbs('Opérations', 'Monitoring');
  clearInterval(timer);
  if (!app.can('monitoring')) { mount(root, h('div', { class: 'card' }, h('div', { class: 'empty' }, 'Réservé à la Blue Team, aux auditeurs et à l\'administrateur.'))); return; }
  const table = h('div', {});
  const chart = h('div', {});
  const updated = h('span', { class: 'faint', style: { fontSize: '12px' } });
  const load = async () => {
    if (!root.isConnected) { clearInterval(timer); return; }
    const { events } = await api.get(`/events${qs({ limit: 300, ...filters })}`);
    mount(table, dataTable({ rows: events, pageSize: 14, initialSort: { key: 'at', dir: 'desc' }, columns: [
      { key: 'at', label: 'Horodatage', render: (e) => h('span', { class: 'mono faint', style: { fontSize: '11.5px' } }, fmtTime(e.at)) },
      { key: 'severity', label: 'Sévérité', render: (e) => h('span', { class: 'badge', style: { color: sevColor(e.severity), background: 'var(--bg-2)' } }, SEV[e.severity] || e.severity) },
      { key: 'rule', label: 'Règle', render: (e) => h('span', { class: 'mono', style: { fontWeight: 600 } }, e.rule) },
      { key: 'message', label: 'Événement', cls: 'title-cell' },
      { key: 'team', label: 'Équipe', render: (e) => (e.team ? teamPill(e.team, app.meta) : '—') },
      { key: 'component', label: 'Composant' },
      { key: 'mode', label: 'Mode', render: (e) => (e.mode === 'hardened' ? badge('Durci', 'b-success') : badge('Vulnérable', 'b-danger')) },
      { key: 'execution_id', label: 'Exécution', render: (e) => h('span', { class: 'mono', style: { fontSize: '12px' } }, e.execution_id || '—') }] }));
    const byRule = {};
    for (const e of events) byRule[e.rule] = (byRule[e.rule] || 0) + 1;
    const rules = Object.keys(byRule).sort();
    mount(chart, rules.length ? [bars({ categories: rules.map((r) => r.replace('DET-', '')), series: [{ name: 'Événements', color: 'var(--secondary)', values: rules.map((r) => byRule[r]) }], height: 190 }),
      legend([{ label: 'Événements par règle', color: 'var(--secondary)' }])] : h('div', { class: 'empty' }, 'Aucun événement.'));
    updated.textContent = `Mis à jour ${new Date().toLocaleTimeString('fr-FR')}`;
  };
  const sel = (key, label, opts) => h('select', { class: 'select', style: { width: 'auto' }, 'aria-label': label, onchange: (e) => { filters[key] = e.target.value; load(); } },
    h('option', { value: '' }, label), opts.map(([v, l]) => h('option', { value: v, selected: filters[key] === v }, l)));
  mount(root,
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', { class: 'page-title' }, 'Monitoring'),
      h('p', { class: 'page-sub' }, 'Les règles de détection analysent les artefacts observables de chaque exécution (entrées, sorties, appels d\'outils, décisions des contrôles), indépendamment du mode et du scénario.')),
    h('div', { class: 'head-actions' }, sel('team', 'Toutes les équipes', ['AGT', 'LLM', 'RAG'].map((t) => [t, app.meta.teams[t].short])),
      sel('severity', 'Toutes sévérités', Object.entries(SEV)),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: auto, onchange: (e) => { auto = e.target.checked; clearInterval(timer); if (auto) timer = setInterval(load, 10000); } }), 'Actualisation auto (10 s)'), updated)),
    h('div', { class: 'grid g-side' },
      card('Règles de détection', `${app.meta.detection_rules.length} règles actives`, h('div', { class: 'list' }, app.meta.detection_rules.map((r) => h('div', { class: 'li', style: { padding: '8px 18px' } },
        h('span', { class: 'mono', style: { fontWeight: 600, fontSize: '12px', width: '90px' } }, r.id), h('div', { class: 'li-main li-sub' }, r.name),
        h('span', { class: 'badge', style: { color: sevColor(r.severity), background: 'var(--bg-2)' } }, SEV[r.severity]))))),
      card('Volume par règle', null, h('div', { class: 'card-body' }, chart))),
    h('div', { class: 'mt' }, card('Flux des événements', null, table)));
  await load();
  if (auto) timer = setInterval(load, 10000);
}
