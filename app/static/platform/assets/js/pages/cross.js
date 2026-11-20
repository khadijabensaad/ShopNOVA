// Cross-Component Attack Analysis : propagation RAG → LLM → Agent → MCP, en 3D, avec points de détection et de mitigation.
import { api } from '../api.js';
import { h, icon, mount, card, empty, badge, teamPill, fmtTime, statusBadge, sevBadge, showTip, hideTip, outcomeBadge, modeBadge, toast } from '../ui.js';
import { sceneBox } from '../scene3d.js';
import { setCrumbs, notifyChanged } from '../main.js';
import { openFinding, openEvidence } from '../finding.js';
import { chainView } from './team.js';

const STATUS_COLOR = { propagated: 'var(--critical)', blocked: 'var(--success)', mitigated: 'var(--warning)', simulated: 'var(--text-3)', idle: 'var(--border-strong)' };

export async function render(root, { app }) {
  setCrumbs('Défense', 'Cross-Component Attack Analysis');
  const [{ incidents }, { findings }] = await Promise.all([api.get('/incidents'), api.get('/findings')]);
  const inc = incidents[0];
  const stages = inc?.stages || [];
  let events = [];
  if (inc?.last_execution_id && app.can(`evidence:${inc.entry_team}`)) {
    try { events = (await api.get(`/executions/${inc.last_execution_id}`)).events; } catch { /* lecture restreinte */ }
  }
  const finding = inc ? findings.find((f) => f.id === inc.finding_id) : null;
  const reload = () => render(root, { app });
  const canRun = app.can('run:XC');
  const run = async (mode, btn) => {
    btn.classList.add('busy');
    try {
      const r = await api.post('/scenarios/XC-S01/run', { mode });
      toast(r.outcome === 'attack_succeeded' ? 'Chaîne complète : exfiltration confirmée via MCP' : `Chaîne interrompue par ${r.blocked_by}`, r.outcome === 'attack_succeeded' ? 'warn' : 'ok');
      notifyChanged(); reload();
    } catch (e) { toast(e.message, 'err'); btn.classList.remove('busy'); }
  };
  const st = (id) => stages.find((s) => s.id === id)?.status || 'idle';
  const detected = new Set(events.map((e) => e.rule));
  const path = [
    { id: 'attacker', label: 'Attaquant', pos: [-4.1, 0.9, 0.9], shape: 'disc', color: 'var(--critical)', dashed: true, glyph: '!', status: 'propagated', info: ['Point d\'entrée', 'Avis client rédigé par l\'attaquant (RAG Attack Team, propriétaire initial).'] },
    { id: 'ingestion', label: 'RAG Ingestion', pos: [-2.7, 0.2, 0], shape: 'card', team: 'RAG', info: ['RAG — ingestion', 'Passerelle de modération de l\'avis.'] },
    { id: 'context', label: 'Retrieved Context', pos: [-1.2, 0.3, -1], shape: 'card', team: 'RAG', info: ['RAG — contexte', 'L\'avis est récupéré et inséré dans le prompt.'] },
    { id: 'llm', label: 'LLM', pos: [0.3, 0.35, -0.6], shape: 'sphere', team: 'LLM', info: ['LLM — interprétation', 'Le modèle lit l\'instruction cachée (chemin simulé, vérifié par AGT-S10/RAG-S11).'] },
    { id: 'agent', label: 'AI Agent', pos: [1.8, 0.3, 0.4], shape: 'sphere', team: 'AGT', info: ['Agent — décision', 'Décision supposée : send_email vers l\'attaquant (chemin simulé).'] },
    { id: 'mcp', label: 'MCP send_email', pos: [3.2, 0.1, -0.3], shape: 'cube', team: 'AGT', info: ['MCP — autorisation', 'Appel réellement exécuté contre le serveur MCP.'] },
    { id: 'exfil', label: 'Exfiltration', pos: [4.3, 1.0, 0.9], shape: 'disc', color: 'var(--critical)', dashed: true, info: ['Impact', 'Données envoyées à un domaine externe.'] },
  ];
  const nodes = path.map((p, i) => {
    const s = p.status || st(p.id);
    const color = p.color || STATUS_COLOR[s];
    return { ...p, r: p.shape === 'sphere' ? 0.36 : p.shape === 'disc' ? 0.28 : 0.27, color, phase: i, hidden: p.id === 'exfil' && st('mcp') !== 'propagated' && stages.length > 0,
      badge: (p.id === 'ingestion' && detected.has('DET-RAG-01')) || (p.id === 'mcp' && (detected.has('DET-TOOL-01') || detected.has('DET-CTL-01'))), badgeColor: 'var(--info)',
      info: [p.info[0], `${p.info[1]} Statut : ${s === 'idle' ? 'non exécuté' : s}.`] };
  });
  const edges = path.slice(1).map((p, i) => {
    const s = i === 0 ? 'propagated' : st(path[i].id);
    return { a: path[i].id, b: p.id, arrow: true, flow: s === 'propagated' || s === 'mitigated' || s === 'simulated', dashed: s === 'simulated' || s === 'idle',
      color: STATUS_COLOR[s === 'idle' ? 'idle' : s], arc: 0.35, particles: 2, speed: 0.5 };
  });
  const { box } = sceneBox({ height: 360, nodes, edges, autoRotate: 0, yaw: 0.02, pitch: 0.36, dist: 10, scale: 0.84, label: 'Chemin d\'attaque multi-composants en 3D',
    rings: [{ radius: 4.6, y: -0.9, color: 'var(--team-blue)', dashed: true, alpha: 0.3, spin: 0.03, label: 'Surveillance Blue Team' }],
    legend: [['var(--critical)', 'Propagée (confirmée)'], ['var(--warning)', 'Atténuée'], ['var(--success)', 'Bloquée'], ['var(--text-3)', 'Chemin simulé'], ['var(--info)', 'Point de détection']],
    onHover: (n, x, y) => (n?.info ? showTip(x, y, n.info[0], n.info[1]) : hideTip()) },
  () => (stages.length ? chainView(stages) : h('div', { class: 'muted' }, 'Aucune chaîne exécutée.')));

  const states = [
    ['Tentative', 'L\'attaque a été lancée', !!inc, 'neutral'],
    ['Attaque confirmée', 'La chaîne a abouti à une action réelle', inc?.status === 'confirmed', 'b-danger'],
    ['Bloquée', 'Un contrôle a interrompu la chaîne', inc?.status === 'blocked', 'b-success'],
    ['Incident détecté', 'Au moins une règle de détection', events.length > 0, 'b-info'],
    ['Vulnérabilité remédiée', 'Finding FIXED ou plus', finding && ['FIXED', 'RETEST_REQUIRED', 'VERIFIED'].includes(finding.status), 'b-primary'],
    ['Correctif vérifié', 'Retest réussi en mode durci', finding?.status === 'VERIFIED', 'b-success'],
  ];
  mount(root,
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', { class: 'page-title' }, 'Propagation d\'une attaque entre composants'),
      h('p', { class: 'page-sub' }, 'Un avis piégé (RAG) est récupéré, interprété par le LLM et pousse l\'agent à invoquer un outil MCP. Le propriétaire initial (RAG Attack Team) reste identifiable ; LLM et AI Agent sont équipes associées — sans finding dupliqué.')),
    h('div', { class: 'head-actions' }, canRun ? [h('button', { class: 'btn', onclick: (e) => run('hardened', e.currentTarget) }, icon('lock'), 'Rejouer (durci)'),
      h('button', { class: 'btn primary', onclick: (e) => run('vulnerable', e.currentTarget) }, icon('play'), 'Exécuter la chaîne (vulnérable)')] : badge('Exécution réservée aux équipes d\'attaque', 'neutral', 'lock'))),
    h('div', { class: 'grid g-main' },
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h3', {}, 'Chemin d\'attaque'), h('span', { class: 'sub' }, inc ? `dernière exécution ${fmtTime(inc.updated_at)}` : 'non exécuté')), h('div', { style: { padding: '12px' } }, box)),
      card('État de l\'incident', inc ? inc.id : '—', h('div', { class: 'card-body' },
        h('div', { class: 'list' }, states.map(([l, d, on, cls]) => h('div', { class: 'li', style: { padding: '9px 0' } },
          h('div', { class: 'li-main' }, h('div', { class: 'li-title' }, l), h('div', { class: 'li-sub' }, d)), on ? badge('Oui', cls, 'check') : badge('Non', 'neutral')))),
        inc ? h('dl', { class: 'kv', style: { marginTop: '12px' } },
          h('dt', {}, 'Point d\'entrée'), h('dd', {}, teamPill(inc.entry_team, app.meta), ' ', inc.entry_component),
          h('dt', {}, 'Équipes associées'), h('dd', {}, inc.collaborating_teams.map((t) => teamPill(t, app.meta))),
          h('dt', {}, 'Composants touchés'), h('dd', {}, inc.components.join(' → ')),
          h('dt', {}, 'Finding unique'), h('dd', {}, finding ? h('button', { class: 'btn sm', onclick: () => openFinding(finding.id, reload) }, finding.id, ' ', statusBadge(finding.status)) : '— (créé si l\'attaque aboutit)')) : null))),
    h('div', { class: 'grid g-2 mt' },
      card('Progression étape par étape', 'confirmé vs simulé', h('div', { class: 'card-body' }, stages.length ? chainView(stages) : empty('network', 'Aucune chaîne exécutée', 'Lancez la chaîne en mode vulnérable puis en mode durci pour comparer les points de blocage.'))),
      card('Points de détection et de mitigation', null, h('div', { class: 'card-body' },
        h('div', { class: 'field' }, h('label', {}, 'Détections (dernière exécution)'), events.length ? h('div', { class: 'list card' }, events.map((e) => h('div', { class: 'li', style: { padding: '8px 12px' } },
          h('span', { class: 'mono', style: { fontWeight: 600, fontSize: '12px' } }, e.rule), h('div', { class: 'li-main li-sub' }, e.message)))) : h('span', { class: 'faint' }, inc ? 'Aucune ou accès restreint.' : '—')),
        h('div', { class: 'field', style: { marginTop: '14px' } }, h('label', {}, 'Mitigation coordonnée recommandée'),
          h('div', { class: 'list card' }, [['RAG', 'Modération à l\'ingestion et provenance (CTL-RAG-01, CTL-RAG-04)'], ['RAG', 'Isolation du contexte non fiable (CTL-RAG-03)'],
            ['LLM', 'Séparation instructions / données dans le prompt'], ['AGT', 'Liste blanche des destinataires (CTL-AGT-05) + approbation humaine (planifiée)']].map(([t, d]) =>
            h('div', { class: 'li', style: { padding: '8px 12px' } }, teamPill(t, app.meta), h('div', { class: 'li-main li-sub' }, d)))))))),
    inc ? card('Exécutions de la chaîne', null, h('div', { class: 'list' }, inc.executions.map((e) => h('div', { class: 'li' },
      h('div', { class: 'li-main' }, h('div', { class: 'li-title mono' }, e.id), h('div', { class: 'li-sub' }, fmtTime(e.started_at))), modeBadge(e.mode),
      outcomeBadge({ status: 'completed', outcome: e.outcome }), e.blocked_by ? badge(e.blocked_by, 'b-success', 'shield') : null)))) : null);
  root.lastChild?.classList?.add('mt');
}
