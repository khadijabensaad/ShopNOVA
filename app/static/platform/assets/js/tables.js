// Tableaux partagés (registre, preuves, historique) : mêmes colonnes et mêmes filtres dans toutes les pages.
import { h, dataTable, sevBadge, statusBadge, teamPill, fmtTime, badge, outcomeBadge, modeBadge, empty, SEV_ORDER, icon } from './ui.js';
import { app } from './main.js';
import { openFinding, openEvidence } from './finding.js';

const STATUS_ORDER = { OPEN: 0, ANALYZED: 1, MITIGATION_IN_PROGRESS: 2, FIXED: 3, RETEST_REQUIRED: 4, VERIFIED: 5 };

export function findingsTable(rows, { onChange, pageSize = 10, hideTeam = false } = {}) {
  const cols = [
    { key: 'id', label: 'ID', render: (f) => h('span', { class: 'mono', style: { fontWeight: 600 } }, f.id) },
    hideTeam ? null : { key: 'team', label: 'Équipe', render: (f) => teamPill(f.team, app.meta) },
    { key: 'title', label: 'Finding', cls: 'title-cell', render: (f) => h('div', {}, h('div', {}, f.title), h('div', { class: 'faint', style: { fontSize: '12px' } }, f.category)) },
    { key: 'component', label: 'Composant' },
    { key: 'severity', label: 'Sévérité', render: (f) => sevBadge(f.severity), sortValue: (f) => -SEV_ORDER[f.severity] },
    { key: 'detection_status', label: 'Détection', render: (f) => f.detection_status === 'detected' ? badge('Détectée', 'b-success') : badge('Non détectée', 'b-warning') },
    { key: 'status', label: 'Statut', render: (f) => statusBadge(f.status), sortValue: (f) => STATUS_ORDER[f.status] },
    { key: 'owner', label: 'Responsable', render: (f) => f.owner || h('span', { class: 'faint' }, '—') },
    { key: 'updated_at', label: 'Mis à jour', render: (f) => h('span', { class: 'mono faint', style: { fontSize: '11.5px' } }, fmtTime(f.updated_at)) },
  ].filter(Boolean);
  return dataTable({ columns: cols, rows, pageSize, onRowClick: (f) => openFinding(f.id, onChange), initialSort: { key: 'severity', dir: 'desc' },
    emptyState: empty('bug', 'Aucun finding', 'Les findings sont créés par les attaques réussies (aucune donnée inventée).') });
}

export function evidenceTable(rows, { pageSize = 12 } = {}) {
  return dataTable({ rows, pageSize, onRowClick: (e) => openEvidence(e.id), initialSort: { key: 'created_at', dir: 'desc' },
    columns: [
      { key: 'id', label: 'Preuve', render: (e) => h('span', { class: 'mono', style: { fontWeight: 600 } }, e.id) },
      { key: 'finding_id', label: 'Finding', render: (e) => e.finding_id ? h('span', { class: 'mono' }, e.finding_id) : h('span', { class: 'faint' }, '—') },
      { key: 'team', label: 'Équipe', render: (e) => teamPill(e.team, app.meta) },
      { key: 'scenario_id', label: 'Scénario', render: (e) => h('span', { class: 'mono' }, e.scenario_id) },
      { key: 'component', label: 'Composant' },
      { key: 'type', label: 'Type', render: (e) => badge(e.type) },
      { key: 'mode', label: 'Mode', render: (e) => modeBadge(e.mode) },
      { key: 'kind', label: 'Nature', render: (e) => badge(e.kind === 'retest' ? 'retest' : e.kind, e.kind === 'retest' ? 'b-info' : 'neutral') },
      { key: 'flags_detected', label: 'Secrets', sortValue: (e) => e.flags_detected.length, render: (e) => e.flags_detected.length ? badge(`${e.flags_detected.length}`, 'b-danger', 'lock') : h('span', { class: 'faint' }, '0') },
      { key: 'created_at', label: 'Horodatage', render: (e) => h('span', { class: 'mono faint', style: { fontSize: '11.5px' } }, fmtTime(e.created_at)) },
    ],
    emptyState: empty('file', 'Aucune preuve', 'Chaque exécution produit une preuve hachée (SHA-256).') });
}

export function executionsTable(rows, { pageSize = 12 } = {}) {
  return dataTable({ rows, pageSize, initialSort: { key: 'started_at', dir: 'desc' }, onRowClick: (e) => e.evidence_id && openEvidence(e.evidence_id),
    columns: [
      { key: 'id', label: 'Exécution', render: (e) => h('span', { class: 'mono', style: { fontWeight: 600 } }, e.id) },
      { key: 'scenario_id', label: 'Scénario', render: (e) => h('span', { class: 'mono' }, e.scenario_id) },
      { key: 'team', label: 'Équipe', render: (e) => teamPill(e.team, app.meta) },
      { key: 'mode', label: 'Mode', render: (e) => modeBadge(e.mode) },
      { key: 'kind', label: 'Nature', render: (e) => badge(e.kind) },
      { key: 'outcome', label: 'Résultat', render: (e) => outcomeBadge(e) },
      { key: 'detected', label: 'Détection', render: (e) => e.detected ? badge('Détectée', 'b-success', 'eye') : h('span', { class: 'faint' }, '—') },
      { key: 'summary', label: 'Résumé', cls: 'title-cell', render: (e) => h('span', { class: 'muted', style: { fontSize: '12.5px' } }, e.summary || '') },
      { key: 'username', label: 'Par', render: (e) => h('span', { class: 'mono', style: { fontSize: '12px' } }, e.username) },
      { key: 'started_at', label: 'Date', render: (e) => h('span', { class: 'mono faint', style: { fontSize: '11.5px' } }, fmtTime(e.started_at)) },
    ],
    emptyState: empty('clock', 'Aucune exécution', 'Lancez un scénario depuis un espace d\'équipe.') });
}

export function filterBar(defs, onChange) {
  // defs : [{key, type:'search'|'select', label, options:[[value,label]]}]
  const state = {};
  const bar = h('div', { class: 'filters' });
  for (const d of defs) {
    state[d.key] = '';
    if (d.type === 'search') {
      bar.append(h('input', { class: 'input', type: 'search', placeholder: d.label, 'aria-label': d.label, oninput: (e) => { state[d.key] = e.target.value.toLowerCase(); onChange(state); } }));
    } else {
      bar.append(h('select', { class: 'select', 'aria-label': d.label, onchange: (e) => { state[d.key] = e.target.value; onChange(state); } },
        h('option', { value: '' }, d.label), d.options.map(([v, l]) => h('option', { value: v }, l))));
    }
  }
  return { bar, state };
}
