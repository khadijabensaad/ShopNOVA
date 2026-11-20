// AI Security Command Center : l'essentiel en un écran — architecture 3D, 4 indicateurs clés, les trois équipes,
// l'activité récente. Les analyses détaillées (graphiques, heatmap, chronologie) sont dans Rapports.
import { api, qs } from '../api.js';
import { h, icon, mount, card, seg, empty, badge, sevBadge, statusBadge, teamPill, ago, pct, toast, TEAM_ICON, showTip, hideTip, withTip } from '../ui.js';
import { ring } from '../charts.js';
import { sceneBox } from '../scene3d.js';
import { setCrumbs, sevColor } from '../main.js';
import { openFinding } from '../finding.js';

const RANGES = [['1', '24 h'], ['7', '7 j'], ['30', '30 j'], ['all', 'Tout']];
let range = 'all';

export async function render(root, { app }) {
  setCrumbs('Command Center');
  const runnable = ['AGT', 'LLM', 'RAG'].filter((t) => app.can(`run:${t}`));
  const since = range === 'all' ? '' : String(Math.floor(Date.now() / 1000 - Number(range) * 86400));
  const [m, ev, fs] = await Promise.all([api.get(`/metrics${qs({ since })}`), api.get(`/events${qs({ limit: 5 })}`), api.get('/findings')]);
  const g = m.global, T = app.meta.teams;
  const reload = () => render(root, { app });

  const runCampaign = async (btn) => {
    btn.classList.add('busy');
    try {
      for (const t of runnable) await api.post('/campaign', { team: t, include_hardened: false });
      toast('Campagne de référence terminée'); reload();
    } catch (ex) { toast(ex.message, 'err'); btn.classList.remove('busy'); }
  };
  const campaignBtn = () => (runnable.length ? h('button', { class: 'btn primary', onclick: (e) => runCampaign(e.currentTarget) }, icon('play'), 'Lancer la campagne de référence') : null);

  const body = h('div', {});
  mount(root,
    h('div', { class: 'page-head' },
      h('div', { class: 'titles' }, h('h1', { class: 'page-title' }, 'AI Security Command Center'),
        h('p', { class: 'page-sub' }, 'La posture de sécurité de l\'assistante Nova, mesurée uniquement à partir des tests réellement exécutés.')),
      h('div', { class: 'head-actions' }, seg(RANGES, range, (v) => { range = v; reload(); }),
        h('button', { class: 'icon-btn', onclick: reload, 'aria-label': 'Actualiser', title: 'Actualiser' }, icon('refresh')), campaignBtn())),
    body);

  if (!m.has_data) {
    body.append(h('div', { class: 'card', style: { marginBottom: '18px' } }, empty('nova', range === 'all' ? 'Aucun test exécuté pour le moment' : 'Aucun test sur cette période',
      'Lancez la campagne de référence : chaque équipe exécute ses scénarios contre le lab, et les vulnérabilités trouvées apparaissent ici.',
      campaignBtn() || h('span', { class: 'faint' }, 'Votre rôle ne permet pas de lancer de campagne.'))));
  }

  // ---------------------------------------------------------------- hero : architecture 3D + indicateurs clés
  const openBy = (t) => m.teams[t].open_vulnerabilities;
  const node = (id, pos, r, color, label, extra = {}) => ({ id, pos, r, color, label, ...extra });
  const nodes = [
    node('core', [0, 0, 0], 0.55, 'var(--primary)', 'Nova', { halo: true, info: ['Nova', 'Orchestrateur : prompt système, contexte, outils.'] }),
    node('agent', [-2.3, 0.1, 1.15], 0.4, 'var(--team-agt)', 'AI Agent', { badge: openBy('AGT') > 0, href: '/team/AGT', team: 'AGT', info: ['AI Agent', `ReAct + MCP · ${openBy('AGT')} vulnérabilité(s) ouverte(s)`] }),
    node('llm', [2.3, 0.1, 1.15], 0.4, 'var(--team-llm)', 'LLM', { badge: openBy('LLM') > 0, href: '/team/LLM', team: 'LLM', info: ['LLM', `Qwen via Ollama · ${openBy('LLM')} vulnérabilité(s) ouverte(s)`] }),
    node('rag', [0, 0.15, -2.45], 0.4, 'var(--team-rag)', 'RAG', { badge: openBy('RAG') > 0, href: '/team/RAG', team: 'RAG', info: ['RAG', `ChromaDB · ${openBy('RAG')} vulnérabilité(s) ouverte(s)`] }),
    node('mcp', [-3.1, -0.55, 2.25], 0.22, 'var(--team-agt)', 'MCP', { shape: 'cube', info: ['Serveur MCP', 'get_customer, get_order, refund, send_email, mémoire.'] }),
    node('chroma', [1.05, -0.55, -3.45], 0.22, 'var(--team-rag)', 'ChromaDB', { shape: 'cube', info: ['ChromaDB', 'FAQ officielle et avis clients.'] }),
    node('t1', [-3.3, 0.95, 0.7], 0.3, 'var(--team-agt)', null, { shape: 'disc', dashed: true, glyph: '01', href: '/team/AGT', team: 'AGT', info: [T.AGT.name, T.AGT.mission] }),
    node('t2', [3.3, 0.95, 0.7], 0.3, 'var(--team-llm)', null, { shape: 'disc', dashed: true, glyph: '02', href: '/team/LLM', team: 'LLM', info: [T.LLM.name, T.LLM.mission] }),
    node('t3', [-1.3, 1.0, -3.1], 0.3, 'var(--team-rag)', null, { shape: 'disc', dashed: true, glyph: '03', href: '/team/RAG', team: 'RAG', info: [T.RAG.name, T.RAG.mission] }),
  ];
  const edges = [
    { a: 'agent', b: 'core', flow: true, color: 'var(--team-agt)' }, { a: 'llm', b: 'core', flow: true, color: 'var(--team-llm)' },
    { a: 'rag', b: 'core', flow: true, color: 'var(--team-rag)' }, { a: 'agent', b: 'mcp', color: 'var(--team-agt)', arc: 0.1 },
    { a: 'rag', b: 'chroma', color: 'var(--team-rag)', arc: 0.1 },
    { a: 't1', b: 'agent', dashed: true, arrow: true, color: 'var(--team-agt)', arc: 0.2 }, { a: 't2', b: 'llm', dashed: true, arrow: true, color: 'var(--team-llm)', arc: 0.2 },
    { a: 't3', b: 'rag', dashed: true, arrow: true, color: 'var(--team-rag)', arc: 0.2 },
  ];
  const { box } = sceneBox({ height: 400, scale: 0.78, dist: 10, pitch: 0.34, offsetY: 18, nodes, edges, grid: false, label: 'Architecture 3D : composants IA, équipes d\'attaque et couche défensive',
    rings: [{ radius: 3.25, y: -0.35, color: 'var(--team-blue)', dashed: true, spin: 0.05, label: 'Blue Team', width: 2 }],
    legend: [['var(--team-agt)', 'AI Agent'], ['var(--team-llm)', 'LLM'], ['var(--team-rag)', 'RAG'], ['var(--team-blue)', 'Blue Team'], ['var(--critical)', 'Vulnérabilité ouverte']],
    onHover: (n, x, y) => (n?.info ? showTip(x, y, n.info[0], n.info[1]) : hideTip()),
    onClick: (n) => { if (n.href && (!n.team || app.can(`evidence:${n.team}`))) location.hash = n.href; else if (n.href) toast('Espace réservé à cette équipe.', 'warn'); },
  }, () => h('div', { class: 'stage-grid' }, nodes.filter((n) => n.href).map((n) => h('a', { class: 'stage', href: `#${n.href}` }, h('b', {}, n.info[0])))));

  const kpi = (label, v, unit, key, color) => {
    const none = v === null || v === undefined;
    const c = h('div', { class: `card kpi ${none ? 'empty' : ''}` }, h('div', { class: 'label' }, label),
      h('div', { class: 'value' }, none ? '—' : v, !none && unit ? h('small', {}, unit) : null),
      color && !none ? h('div', { class: 'viz' }, ring(v, color, 36)) : null);
    return withTip(c, label, m.definitions[key]);
  };
  const most = m.most_vulnerable;
  const side = h('div', { class: 'hero-side' },
    h('div', { class: 'kpi-pair' },
      kpi('Vulnérabilités ouvertes', g.total_vulnerabilities ? g.open_vulnerabilities : null, '', 'critical_high'),
      kpi('Risque résiduel', g.residual_risk, '%', 'residual_risk', 'var(--critical)'),
      kpi('Attaques réussies', g.attack_success_rate, '%', 'attack_success_rate', 'var(--warning)'),
      kpi('Attaques détectées', g.detection_rate, '%', 'detection_rate', 'var(--success)')),
    h('div', { class: 'card card-body' }, h('h3', { style: { fontSize: '15.5px', marginBottom: '4px' } }, 'Composant le plus exposé'),
      h('p', { class: 'muted', style: { margin: '0 0 12px', fontSize: '13px' } }, most ? `${most.component} — ${most.critical_high} vulnérabilité(s) critique(s) ou élevée(s) ouverte(s).` : 'Disponible après les premiers tests.'),
      ['AGT', 'LLM', 'RAG'].map((t) => h('div', { class: 'rank-row', 'data-team': t }, teamPill(t, app.meta),
        h('div', { class: 'meter' }, h('i', { style: { width: `${m.teams[t].residual_risk || 0}%` } })), h('span', { class: 'mono', style: { textAlign: 'right' } }, pct(m.teams[t].residual_risk))))));
  body.append(h('div', { class: 'hero' }, h('div', { class: 'card', style: { padding: '12px' } }, box), side));
  body.append(h('div', { class: 'card mt mini-stats' },
    h('span', {}, 'Faux positifs', h('b', {}, pct(g.false_positive_rate))), h('span', {}, 'Remédiation', h('b', {}, pct(g.remediation_rate))),
    h('span', {}, 'Retests réussis', h('b', {}, pct(g.retest_pass_rate))), h('span', {}, 'Temps moyen de détection', h('b', {}, g.mttd_ms === null ? '—' : `${g.mttd_ms} ms`)),
    h('span', {}, 'Temps moyen de correction', h('b', {}, g.mttr_h === null ? '—' : `${g.mttr_h} h`)),
    h('a', { href: '#/reports', style: { marginLeft: 'auto', fontWeight: 700 } }, 'Voir les rapports détaillés')));

  // ---------------------------------------------------------------- les trois équipes
  body.append(h('div', { class: 'section-title' }, h('h2', {}, 'Les trois équipes d\'attaque')));
  body.append(h('div', { class: 'grid g-3' }, ['AGT', 'LLM', 'RAG'].map((t) => {
    const tm = m.teams[t], ok = app.can(`evidence:${t}`);
    return h('div', { class: 'card team-card', 'data-team': t },
      h('div', { class: 'tc-head' }, h('div', { class: 'team-ic' }, icon(TEAM_ICON[t])),
        h('div', { style: { flex: 1 } }, h('div', { class: 'tc-title' }, `Team ${T[t].number} · ${T[t].short}`), h('div', { class: 'tc-sub' }, T[t].subtitle))),
      h('div', { class: 'tc-stats' },
        h('div', { class: 'tc-stat' }, h('b', {}, tm.tests), h('span', {}, 'tests')),
        h('div', { class: 'tc-stat' }, h('b', { style: { color: tm.successful_attacks ? 'var(--critical)' : null } }, tm.successful_attacks), h('span', {}, 'attaques réussies')),
        h('div', { class: 'tc-stat' }, h('b', {}, tm.open_vulnerabilities), h('span', {}, 'ouvertes'))),
      h('div', {}, h('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '6px' } }, h('span', { class: 'muted' }, 'Détection'), h('b', {}, pct(tm.detection_rate))),
        h('div', { class: 'meter' }, h('i', { style: { width: `${tm.detection_rate || 0}%` } }))),
      h('div', { class: 'tc-foot' }, h('span', {}, `Retests : ${tm.retest_status}`),
        ok ? h('a', { class: 'btn sm', href: `#/team/${t}` }, 'Ouvrir l\'espace') : badge('Accès réservé', 'neutral', 'lock')));
  })));

  // ---------------------------------------------------------------- activité récente
  const fsLatest = fs.findings.slice(0, 5);
  body.append(h('div', { class: 'grid g-2 mt-l' },
    card('Événements récents', null, h('div', { class: 'list' }, ev.events.length ? ev.events.map((e) => h('div', { class: 'li' },
      h('i', { class: 'ev-sev', style: { background: sevColor(e.severity) } }),
      h('div', { class: 'li-main' }, h('div', { class: 'li-title' }, e.message.split(' — ')[0]), h('div', { class: 'li-sub' }, e.message.split(' — ')[1] || '')),
      e.team ? teamPill(e.team, app.meta) : null, h('span', { class: 'li-time' }, ago(e.at)))) : empty('activity', 'Aucun événement', 'La surveillance analyse chaque test exécuté.')),
    app.can('monitoring') ? h('a', { class: 'btn sm ghost', href: '#/monitoring' }, 'Tout voir') : null),
    card('Dernières vulnérabilités', null, h('div', { class: 'list' }, fsLatest.length ? fsLatest.map((f) => h('div', { class: 'li', style: { cursor: 'pointer' }, tabindex: '0', onclick: () => openFinding(f.id, reload), onkeydown: (e) => { if (e.key === 'Enter') openFinding(f.id, reload); } },
      h('div', { class: 'li-main' }, h('div', { class: 'li-title' }, f.title), h('div', { class: 'li-sub' }, h('span', { class: 'mono' }, f.id), ` · ${f.component}`)),
      sevBadge(f.severity), statusBadge(f.status))) : empty('bug', 'Registre vide', 'Une attaque réussie crée automatiquement une vulnérabilité.')),
    h('a', { class: 'btn sm ghost', href: '#/registry' }, 'Tout voir'))));
}
