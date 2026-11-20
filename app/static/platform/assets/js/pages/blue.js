// AI Security Defense Center (Blue Team partagée) : boîte de réception, tableau de remédiation, contrôles, audit.
import { api } from '../api.js';
import { h, icon, mount, card, tabs, empty, badge, sevBadge, statusBadge, teamPill, fmtTime, dataTable, STATUS_LABEL } from '../ui.js';
import { setCrumbs } from '../main.js';
import { openFinding } from '../finding.js';
import { findingsTable, filterBar } from '../tables.js';

let tab = 'inbox';
const FLOW = ['OPEN', 'ANALYZED', 'MITIGATION_IN_PROGRESS', 'FIXED', 'RETEST_REQUIRED', 'VERIFIED'];

export async function render(root, { app }) {
  setCrumbs('Défense', 'Centre de défense');
  if (!(app.can('triage') || app.can('audit:read'))) {
    mount(root, h('div', { class: 'card' }, empty('lock', 'Espace Blue Team', 'Réservé à la Blue Team, aux auditeurs et à l\'administrateur (contrôle serveur).'))); return;
  }
  const { findings } = await api.get('/findings');
  const reload = () => render(root, { app });
  const c = (s) => findings.filter((f) => s.includes(f.status)).length;
  const counters = [
    ['Findings ouverts', findings.filter((f) => f.status !== 'VERIFIED').length, 'bug', 'var(--critical)'],
    ['Critiques ouverts', findings.filter((f) => f.status !== 'VERIFIED' && f.severity === 'critical').length, 'alert', 'var(--critical)'],
    ['En remédiation', c(['ANALYZED', 'MITIGATION_IN_PROGRESS']), 'tool', 'var(--info)'],
    ['Corrigés (FIXED)', c(['FIXED']), 'check', 'var(--primary)'],
    ['Retest requis', c(['RETEST_REQUIRED']), 'refresh', 'var(--secondary)'],
    ['Vérifiés', c(['VERIFIED']), 'shield', 'var(--success)'],
  ];
  const body = h('div', {});
  mount(root,
    h('div', { class: 'page-head', 'data-team': 'BLUE' }, h('div', { class: 'titles' },
      h('div', { class: 'eyebrow' }, h('span', { class: 'team-pill', 'data-team': 'BLUE' }, h('span', { class: 'num' }, 'BT'), 'Blue Team partagée')),
      h('h1', { class: 'page-title' }, 'Centre de défense'),
      h('p', { class: 'page-sub' }, 'Une défense centralisée pour les findings des trois équipes. Un finding n\'est VERIFIED qu\'après un retest réel en mode durci : aucun changement de statut manuel ne vaut vérification.')),
    h('div', { class: 'head-actions' }, app.can('triage') ? badge('Droits de triage', 'b-success', 'shield') : badge('Lecture seule (audit)', 'neutral', 'eye'))),
    h('div', { class: 'grid', style: { gridTemplateColumns: 'repeat(6, minmax(0,1fr))' } }, counters.map(([l, v, ic, col]) => h('div', { class: 'card kpi' },
      h('div', { class: 'label' }, h('span', { style: { color: col, display: 'inline-flex' } }, icon(ic)), l), h('div', { class: 'value' }, v)))),
    h('div', { class: 'mt-l', 'data-team': 'BLUE' }, tabs([['inbox', 'Findings Inbox', findings.length], ['board', 'Remediation Workflow'], ['controls', 'Security Controls'],
      app.can('audit:read') ? ['audit', 'Audit Log'] : null].filter(Boolean), tab, (t) => { tab = t; reload(); })),
    body);

  if (tab === 'inbox') {
    const table = findingsTable(findings, { onChange: reload, pageSize: 12 });
    const { bar } = filterBar([
      { key: 'q', type: 'search', label: 'Rechercher un ID ou un titre' },
      { key: 'team', type: 'select', label: 'Équipe', options: ['AGT', 'LLM', 'RAG'].map((t) => [t, app.meta.teams[t].short]) },
      { key: 'severity', type: 'select', label: 'Sévérité', options: [['critical', 'Critique'], ['high', 'Élevée'], ['medium', 'Moyenne'], ['low', 'Faible']] },
      { key: 'status', type: 'select', label: 'Statut', options: FLOW.map((s) => [s, STATUS_LABEL[s]]) }],
    (f) => table.update(findings.filter((x) => (!f.q || `${x.id} ${x.title}`.toLowerCase().includes(f.q)) && (!f.team || x.team === f.team)
      && (!f.severity || x.severity === f.severity) && (!f.status || x.status === f.status))));
    mount(body, h('div', { class: 'card' }, bar, table));
  } else if (tab === 'board') {
    mount(body, h('div', {}, h('div', { class: 'note', style: { marginBottom: '12px' } }, 'OPEN → ANALYZED → MITIGATION IN PROGRESS → FIXED → RETEST REQUIRED → VERIFIED. Cliquez une carte pour agir. La dernière transition est réservée au retest automatique.'),
      h('div', { class: 'kanban' }, FLOW.map((s) => {
        const items = findings.filter((f) => f.status === s);
        return h('div', { class: 'kcol' }, h('h4', {}, statusBadge(s), h('span', {}, items.length)),
          items.length ? items.map((f) => h('div', { class: 'kcard', tabindex: '0', onclick: () => openFinding(f.id, reload), onkeydown: (e) => { if (e.key === 'Enter') openFinding(f.id, reload); } },
            h('div', { style: { display: 'flex', gap: '6px', alignItems: 'center' } }, h('span', { class: 'mono', style: { fontWeight: 600, fontSize: '11.5px' } }, f.id), sevBadge(f.severity)),
            h('div', { class: 't' }, f.title), h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } }, teamPill(f.team, app.meta),
              h('span', { class: 'faint', style: { fontSize: '11px' } }, f.owner || 'non assigné')))) : h('div', { class: 'faint', style: { fontSize: '12px', padding: '6px' } }, 'Vide'));
      }))));
  } else if (tab === 'controls') {
    const { controls } = await api.get('/controls');
    const areas = [['AGT', 'Agent Defense'], ['LLM', 'LLM Defense'], ['RAG', 'RAG Defense']];
    const st = { implemented: ['Implémenté', 'b-success'], partial: ['Partiel', 'b-warning'], planned: ['Planifié', 'neutral'] };
    mount(body, h('div', {}, h('div', { class: 'note', style: { marginBottom: '12px' } }, h('b', {}, 'Statut : '), 'décrit le code réel du mode durci. ', h('b', {}, 'Validation : '),
      'calculée à partir des dernières exécutions en mode durci des scénarios liés (réussie si toutes les attaques sont bloquées).'),
    h('div', { class: 'grid g-3' }, areas.map(([t, title]) => h('div', { class: 'card', 'data-team': t }, h('div', { class: 'card-head' }, teamPill(t, app.meta), h('h3', {}, title)),
      h('div', { class: 'list' }, controls.filter((x) => x.area === t).map((x) => h('div', { class: 'li' },
        h('div', { class: 'li-main' }, h('div', { class: 'li-title' }, h('span', { class: 'mono faint', style: { fontSize: '11px' } }, x.id), ' ', x.name),
          h('div', { class: 'li-sub' }, x.description), h('div', { class: 'faint mono', style: { fontSize: '11px', marginTop: '3px' } }, x.implementation)),
        h('div', { style: { display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'flex-end' } }, badge(st[x.status][0], st[x.status][1]),
          x.validation === 'pass' ? badge('Validé', 'b-success', 'check') : x.validation === 'fail' ? badge('Contourné', 'b-danger', 'alert') : badge('Non testé', 'neutral'))))))))));
  } else {
    const { audit } = await api.get('/audit?limit=500');
    mount(body, card('Journal d\'audit', 'opérations d\'administration et de sécurité', dataTable({ rows: audit, pageSize: 15, initialSort: { key: 'at', dir: 'desc' }, columns: [
      { key: 'at', label: 'Horodatage', render: (a) => h('span', { class: 'mono faint', style: { fontSize: '11.5px' } }, fmtTime(a.at)) },
      { key: 'username', label: 'Utilisateur', render: (a) => h('span', { class: 'mono' }, a.username || '—') },
      { key: 'role', label: 'Rôle', render: (a) => a.role || h('span', { class: 'faint' }, '—') },
      { key: 'action', label: 'Action', render: (a) => badge(a.action, a.action.includes('failed') ? 'b-danger' : 'neutral') },
      { key: 'target', label: 'Cible', render: (a) => h('span', { class: 'mono' }, a.target || '—') },
      { key: 'details', label: 'Détails', sortable: false, render: (a) => h('span', { class: 'mono faint', style: { fontSize: '11px' } }, JSON.stringify(a.details || {}).slice(0, 90)) },
      { key: 'ip', label: 'IP', render: (a) => h('span', { class: 'mono faint' }, a.ip) }] })));
  }
}
