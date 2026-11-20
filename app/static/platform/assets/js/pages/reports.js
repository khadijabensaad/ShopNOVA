// Reports : analyses filtrables (équipe, composant, sévérité, statut, période) et export HTML du rapport.
import { api, qs } from '../api.js';
import { h, icon, mount, card, badge, pct, SEV, empty, dataTable, sevBadge, statusBadge, teamPill } from '../ui.js';
import { bars, donut, legend, hstack, timeline } from '../charts.js';
import { setCrumbs, sevColor } from '../main.js';

const f = { team: '', severity: '', status: '', component: '', period: 'all' };

export async function render(root, { app }) {
  setCrumbs('Laboratoire', 'Reports');
  const since = f.period === 'all' ? '' : String(Math.floor(Date.now() / 1000 - Number(f.period) * 86400));
  const [m, fs, inc] = await Promise.all([api.get(`/metrics${qs({ since })}`), api.get('/findings'), api.get('/incidents')]);
  const reload = () => render(root, { app });
  const teams = f.team ? [f.team] : ['AGT', 'LLM', 'RAG'];
  const findings = fs.findings.filter((x) => (!f.team || x.team === f.team) && (!f.severity || x.severity === f.severity) && (!f.status || x.status === f.status)
    && (!f.component || x.component === f.component) && (!since || x.updated_at >= Number(since)));
  const sel = (key, label, opts) => h('select', { class: 'select', style: { width: 'auto' }, 'aria-label': label, onchange: (e) => { f[key] = e.target.value; reload(); } },
    h('option', { value: key === 'period' ? 'all' : '' }, label), opts.map(([v, l]) => h('option', { value: v, selected: f[key] === v }, l)));
  const exportUrl = `/api/secops/reports/export${qs({ team: f.team, severity: f.severity, status: f.status })}`;
  const lbl = teams.map((t) => app.meta.teams[t].short);
  const STC = { OPEN: 'var(--critical)', ANALYZED: 'var(--warning)', MITIGATION_IN_PROGRESS: 'var(--info)', FIXED: 'var(--primary)', RETEST_REQUIRED: 'var(--secondary)', VERIFIED: 'var(--success)' };
  const sevItems = ['critical', 'high', 'medium', 'low'].map((s) => ({ label: SEV[s], value: findings.filter((x) => x.severity === s).length, color: sevColor(s) }));
  const comps = [...new Set(fs.findings.map((x) => x.component))].sort();
  mount(root,
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', { class: 'page-title' }, 'Rapports'),
      h('p', { class: 'page-sub' }, 'Toutes les analyses sont calculées à partir des enregistrements du backend. L\'export produit un rapport HTML autonome (testé), imprimable en PDF depuis le navigateur.')),
    h('div', { class: 'head-actions' }, app.can('report:export') ? h('a', { class: 'btn primary', href: exportUrl, download: 'shopnova-security-report.html' }, icon('download'), 'Exporter le rapport (HTML)')
      : badge('Export réservé : Blue Team, auditeur, admin', 'neutral', 'lock'))),
    h('div', { class: 'card', style: { marginBottom: '16px' } }, h('div', { class: 'filters', style: { borderBottom: 0 } },
      sel('team', 'Toutes les équipes', ['AGT', 'LLM', 'RAG'].map((t) => [t, app.meta.teams[t].name])), sel('component', 'Tous composants', comps.map((c) => [c, c])),
      sel('severity', 'Toutes sévérités', Object.entries(SEV)), sel('status', 'Tous statuts', app.meta.statuses.map((s) => [s, s])),
      sel('period', 'Toute la période', [['1', 'Dernières 24 h'], ['7', '7 jours'], ['30', '30 jours']]),
      h('span', { class: 'faint', style: { marginLeft: 'auto', fontSize: '12px' } }, `${findings.length} finding(s) dans le périmètre`))),
    !m.has_data ? h('div', { class: 'card' }, empty('report', 'Aucune donnée à analyser', 'Exécutez des scénarios depuis les espaces d\'équipe : les rapports se remplissent automatiquement.')) : h('div', {},
      h('div', { class: 'grid g-3' },
        card('Attack success by team', 'avant / après durcissement', h('div', { class: 'card-body' }, bars({ categories: lbl, height: 200, unit: '%', max: 100, series: [
          { name: 'Vulnérable', color: 'var(--critical)', values: teams.map((t) => m.teams[t].attack_success_rate || 0) },
          { name: 'Durci', color: 'var(--success)', values: teams.map((t) => m.teams[t].hardened_success_rate || 0) }] }),
        legend([{ label: 'Mode vulnérable', color: 'var(--critical)' }, { label: 'Mode durci', color: 'var(--success)' }]))),
        card('Detection rate by team', null, h('div', { class: 'card-body' }, bars({ categories: lbl, height: 200, unit: '%', max: 100, series: [
          { name: 'Détection', color: 'var(--secondary)', values: teams.map((t) => m.teams[t].detection_rate || 0) },
          { name: 'Retests réussis', color: 'var(--success)', values: teams.map((t) => m.teams[t].retest_pass_rate || 0) }] }),
        legend([{ label: 'Taux de détection', color: 'var(--secondary)' }, { label: 'Retests réussis', color: 'var(--success)' }]))),
        card('Severity distribution', 'périmètre filtré', h('div', { class: 'card-body', style: { display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' } }, donut({ items: sevItems, sub: 'findings' }), legend(sevItems)))),
      h('div', { class: 'grid g-2 mt' },
        card('Remediation progress', 'statut par équipe', h('div', { class: 'card-body' }, hstack({ rows: teams.map((t) => ({ label: app.meta.teams[t].short,
          parts: Object.keys(STC).map((s) => ({ label: s, value: findings.filter((x) => x.team === t && x.status === s).length, color: STC[s] })) })) }),
        h('div', { style: { marginTop: '12px' } }, legend(Object.entries(STC).map(([s, c]) => ({ label: s, color: c })))))),
        card('Security activity timeline', null, h('div', { class: 'card-body' }, m.timeline.length ? timeline({ points: m.timeline.map((d) => ({ label: d.day.slice(5), a: d.succeeded, b: d.blocked })) }) : empty('clock', 'Aucune activité', null)))),
      h('div', { class: 'grid g-4 mt' }, [
        ['Remediation rate', pct(m.global.remediation_rate)], ['Retest pass rate', pct(m.global.retest_pass_rate)], ['False positive rate', pct(m.global.false_positive_rate)],
        ['Cross-component incidents', `${inc.incidents.length} (${inc.incidents.filter((i) => i.status === 'confirmed').length} confirmé·s)`]].map(([l, v]) => h('div', { class: 'card kpi' }, h('div', { class: 'label' }, l), h('div', { class: 'value' }, v)))),
      h('div', { class: 'mt' }, card('Findings du périmètre', null, dataTable({ rows: findings, pageSize: 10, columns: [
        { key: 'id', label: 'ID', render: (x) => h('span', { class: 'mono', style: { fontWeight: 600 } }, x.id) }, { key: 'team', label: 'Équipe', render: (x) => teamPill(x.team, app.meta) },
        { key: 'title', label: 'Titre', cls: 'title-cell' }, { key: 'severity', label: 'Sévérité', render: (x) => sevBadge(x.severity) },
        { key: 'status', label: 'Statut', render: (x) => statusBadge(x.status) }, { key: 'retest_result', label: 'Retest', render: (x) => x.retest_result || '—' }] })))));
}
