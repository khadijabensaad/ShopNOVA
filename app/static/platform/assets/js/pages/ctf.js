// CTF Challenges : les 23 défis existants (identifiants, flags, score et API /api/ctf/* inchangés),
// présentés par catégorie et rattachés aux équipes. L'interface historique reste disponible sur /ctf.
import { api } from '../api.js';
import { h, icon, mount, clear, card, tabs, badge, teamPill, toast, confirmDialog, code, empty } from '../ui.js';
import { setCrumbs } from '../main.js';

const CATS = [['WS2', 'LLM Challenges'], ['WS3', 'AI Agent & MCP'], ['WS4', 'Model Security'], ['WS5', 'Blue Team']];
const WS4_OPS = { B1: [['classify', 'Interroger le classificateur'], ['activate_official', 'Modèle officiel']],
  B2: [['classify', 'Interroger'], ['retrain', 'Réentraîner (texte + étiquette)'], ['activate_official', 'Modèle officiel']],
  B3: [['classify', 'Interroger le classificateur'], ['activate_official', 'Modèle officiel']],
  B4: [['upload', 'Importer le JSON comme modèle'], ['activate_custom', 'Activer le modèle personnalisé'], ['activate_official', 'Modèle officiel'], ['classify', 'Interroger']],
  B5: [['classify', 'Interroger le classificateur'], ['activate_official', 'Modèle officiel']] };
const WS5_OPS = { E1: [['test_filter', 'Tester ces mots-clés']], E2: [['read_log', 'Lire le journal'], ['guess', 'Proposer ce numéro']],
  E3: [['order', 'Soumettre cet ordre']], E4: [['answer', 'Soumettre ma réponse']] };
const st = { ws: 'WS2', cur: null, hist: {} };

export async function render(root, { app }) {
  setCrumbs('Laboratoire', 'Défis CTF');
  const [S, map] = await Promise.all([api.ctf.state(), api.get('/ctf/mapping')]);
  const reload = () => render(root, { app });
  if (!st.cur || !S.challenges.find((c) => c.id === st.cur)) st.cur = S.challenges.find((c) => c.ws === st.ws).id;
  const cur = S.challenges.find((c) => c.id === st.cur);
  const list = S.challenges.filter((c) => c.ws === st.ws);
  const detail = h('div', {});
  mount(root,
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', { class: 'page-title' }, 'Défis CTF'),
      h('p', { class: 'page-sub' }, 'Un flag n\'est délivré que lorsque la condition de l\'attaque est réellement vérifiée par le moteur. La réussite d\'une attaque (CTF) est distincte de la remédiation (registre + retest).')),
    h('div', { class: 'head-actions' },
      h('div', { class: 'card', style: { padding: '8px 14px', display: 'flex', gap: '14px', alignItems: 'center' } },
        h('div', {}, h('div', { class: 'faint', style: { fontSize: '11px' } }, 'SCORE'), h('b', { style: { font: '600 20px var(--font-display)' } }, S.score, h('span', { class: 'muted', style: { fontSize: '13px' } }, ` / ${S.max}`))),
        h('div', { style: { width: '140px' } }, h('div', { class: 'faint', style: { fontSize: '11px', marginBottom: '4px' } }, `${S.solved} / ${S.total} résolus`), h('div', { class: 'meter' }, h('i', { style: { width: `${(100 * S.solved) / S.total}%`, background: 'var(--success)' } })))),
      h('a', { class: 'btn', href: '/ctf', target: '_blank', rel: 'noopener' }, icon('external'), 'Interface historique'),
      h('button', { class: 'btn danger', onclick: async () => {
        if (!(await confirmDialog('Réinitialiser le CTF ?', 'Le score, les indices, les avis publiés, la mémoire de l\'agent, la boîte d\'envoi, la note de service et le classificateur seront réinitialisés.', 'Réinitialiser', 'danger'))) return;
        await api.ctf.reset(); st.hist = {}; toast('CTF réinitialisé'); reload();
      } }, icon('refresh'), 'Réinitialiser'))),
    tabs(CATS.map(([w, l]) => [w, l, `${S.challenges.filter((c) => c.ws === w && c.solved).length}/${S.challenges.filter((c) => c.ws === w).length}`]), st.ws,
      (w) => { st.ws = w; st.cur = S.challenges.find((c) => c.ws === w).id; reload(); }),
    h('div', { class: 'ctf-layout' },
      h('div', { class: 'card' }, list.map((c) => h('button', { class: `ch-item ${c.id === st.cur ? 'on' : ''}`, onclick: () => { st.cur = c.id; reload(); } },
        h('span', { class: 'cid' }, c.id), h('span', { class: 'ct' }, c.title, h('div', { class: 'faint', style: { fontSize: '11.5px' } }, `${c.diff} · ${c.points} pts`)),
        c.solved ? h('span', { class: 'ok' }, icon('check')) : null))),
      detail));
  await openChallenge(detail, cur, app, map, reload);
}

async function openChallenge(el, c, app, map, reload) {
  await api.ctf.mode(c.mode === 'secure').catch(() => {});
  const team = app.meta.ctf_team[c.id];
  const hist = st.hist[c.id] || (st.hist[c.id] = []);
  const log = h('div', { class: 'console-log', 'aria-live': 'polite' });
  const trace = h('div', {});
  const say = (cls, text) => { log.append(h('div', { class: `msg ${cls}` }, text)); log.scrollTop = 1e9; };
  say('n', { chat: 'Nova est prête.', review: 'Publie ton avis, puis lance le test client.', agent: 'Nova Agent est connectée au serveur MCP.', notice: 'Modifie la note, puis lance le test client.',
    mcp_raw: 'Appel direct d\'un outil du serveur MCP.', ws4: 'Classificateur de modération prêt.', ws5: 'Prêt.' }[c.target]);
  const handle = (r) => {
    if (r.asked && ['review', 'notice'].includes(c.target)) say('u', `[client test] ${r.asked}`);
    say('n', r.answer || '(réponse vide)');
    if (r.trace?.length) mount(trace, h('div', { class: 'field', style: { marginTop: '10px' } }, h('label', {}, 'Appels d\'outils (trace MCP)'), code(r.trace)));
    if (r.released) { say('f', `FLAG libéré : ${r.released}`); toast('Flag libéré !'); }
  };
  const attempt = async (msg, btn, keep = true) => {
    btn?.classList.add('busy');
    try {
      const r = await api.ctf.attempt(c.id, msg, keep ? hist : []);
      if (keep && ['chat', 'agent'].includes(c.target)) { hist.push({ role: 'user', content: msg }, { role: 'assistant', content: r.answer || '' }); }
      handle(r);
    } catch (e) { say('n', `Erreur : ${e.message}`); } finally { btn?.classList.remove('busy'); }
  };
  let inputs;
  if (c.target === 'chat' || c.target === 'agent') {
    const inp = h('input', { class: 'input', placeholder: c.target === 'chat' ? 'Votre prompt' : 'Votre message à Nova Agent', 'aria-label': 'Message' });
    const go = h('button', { class: 'btn primary', onclick: () => { if (inp.value.trim()) { say('u', inp.value); attempt(inp.value, go); inp.value = ''; } } }, 'Envoyer');
    inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') go.click(); });
    inputs = h('div', { class: 'console-in' }, inp, go, h('button', { class: 'btn ghost', title: 'Nouvelle conversation', onclick: () => { st.hist[c.id] = []; reload(); } }, icon('refresh'), 'Nouvelle conversation'));
  } else if (c.target === 'review' || c.target === 'notice') {
    const ta = h('textarea', { class: 'textarea', rows: 3, placeholder: c.target === 'review' ? 'Texte de l\'avis à publier sur le casque audio' : 'Nouveau texte de la note de service', 'aria-label': 'Texte' });
    inputs = h('div', { class: 'console-in', style: { flexDirection: 'column' } }, ta, h('div', { style: { display: 'flex', gap: '8px' } },
      h('button', { class: 'btn', onclick: async () => {
        try { if (c.target === 'review') await api.ctf.review('Casque audio', 'Joueur', ta.value); else await api.ctf.notice(ta.value); say('u', `[publié] ${ta.value}`); toast('Publié'); }
        catch (e) { say('n', `Refusé : ${e.message}`); }
      } }, c.target === 'review' ? 'Publier l\'avis' : 'Publier la note'),
      h('button', { class: 'btn primary', onclick: (e) => attempt('', e.currentTarget, false) }, 'Lancer le test client')));
  } else if (c.target === 'mcp_raw') {
    const tool = h('input', { class: 'input', placeholder: 'Outil, ex. get_customer', 'aria-label': 'Outil' });
    const args = h('input', { class: 'input', placeholder: 'Arguments JSON, ex. {"customer_id": 13}', 'aria-label': 'Arguments' });
    inputs = h('div', { class: 'console-in' }, tool, args, h('button', { class: 'btn primary', onclick: (e) => {
      let a; try { a = JSON.parse(args.value || '{}'); } catch { toast('JSON invalide', 'err'); return; }
      say('u', `${tool.value}(${JSON.stringify(a)})`); attempt(JSON.stringify({ tool: tool.value, args: a }), e.currentTarget, false);
    } }, 'Appeler l\'outil'));
  } else {
    const txt = h('input', { class: 'input', placeholder: c.target === 'ws4' ? 'Texte à soumettre (ou JSON de modèle pour B4)' : 'Réponse ou mots-clés', 'aria-label': 'Texte' });
    const lbl = c.target === 'ws4' ? h('select', { class: 'select', style: { width: 'auto' }, 'aria-label': 'Étiquette' }, h('option', {}, 'sûr'), h('option', {}, 'malveillant')) : null;
    const ops = (c.target === 'ws4' ? WS4_OPS : WS5_OPS)[c.id] || [];
    inputs = h('div', { class: 'console-in' }, txt, lbl, ops.map(([op, l]) => h('button', { class: 'btn', onclick: (e) => {
      say('u', `${op} · ${txt.value}`); attempt(JSON.stringify({ op, text: txt.value, label: lbl?.value || 'sûr' }), e.currentTarget, false);
    } }, l)));
  }
  const hintsBox = h('div', {}, c.hints_shown.map((x) => h('div', { class: 'note', style: { marginBottom: '6px', borderLeft: '3px solid var(--warning)' } }, x)));
  const flag = h('input', { class: 'input mono', placeholder: 'FLAG{...}', 'aria-label': 'Flag' });
  const fm = h('div', { style: { fontSize: '12.5px', marginTop: '6px' } });
  const scen = map.scenarios[c.id] || [];
  mount(el, h('div', { class: 'card' },
    h('div', { class: 'card-head', style: { flexWrap: 'wrap' } }, h('span', { class: 'mono', style: { fontWeight: 700, color: 'var(--secondary)' } }, c.id), h('h3', {}, c.title),
      team ? teamPill(team, app.meta) : null, badge(c.risk, 'b-primary'), badge(c.diff), c.mode === 'secure' ? badge('Mode sécurisé', 'b-success', 'lock') : badge('Mode vulnérable', 'b-danger'),
      h('div', { class: 'right' }, h('b', { class: 'mono', style: { color: 'var(--warning)' } }, `${c.points} pts`))),
    h('div', { class: 'card-body' },
      h('p', { style: { marginTop: 0, whiteSpace: 'pre-wrap' } }, c.brief),
      h('details', {}, h('summary', { style: { cursor: 'pointer', color: 'var(--secondary)', fontSize: '13px' } }, 'Comprendre'), h('p', { class: 'muted' }, c.learn)),
      scen.length ? h('div', { class: 'faint', style: { fontSize: '12px', margin: '8px 0' } }, 'Scénarios SecOps associés : ', scen.join(', ')) : null,
      h('div', { class: 'console', style: { marginTop: '12px' } }, log, inputs), trace,
      h('div', { class: 'grid g-2 mt' },
        h('div', {}, h('h4', { style: { fontSize: '13px', marginBottom: '8px' } }, 'Indices (−15 % chacun)'), hintsBox,
          c.hints_shown.length < 3 ? h('button', { class: 'btn sm', onclick: async () => { const r = await api.ctf.hint(c.id); mount(hintsBox, r.hints.map((x) => h('div', { class: 'note', style: { marginBottom: '6px', borderLeft: '3px solid var(--warning)' } }, x))); } }, `Révéler l'indice ${c.hints_shown.length + 1}`) : null),
        h('div', {}, h('h4', { style: { fontSize: '13px', marginBottom: '8px' } }, 'Valider le flag'),
          c.solved ? badge(`Validé : +${c.earned} pts`, 'b-success', 'check') : h('div', {}, h('div', { style: { display: 'flex', gap: '8px' } }, flag,
            h('button', { class: 'btn primary', onclick: async () => {
              const r = await api.ctf.submit(c.id, flag.value);
              if (r.ok) { toast(`Flag valide : +${r.points} pts`); reload(); } else { mount(fm, h('span', { style: { color: 'var(--critical)' } }, 'Flag incorrect.')); }
            } }, 'Valider')), fm))),
      c.solved && c.fix ? h('div', { class: 'note', style: { marginTop: '14px', borderLeft: '3px solid var(--success)' } }, h('b', {}, 'Mitigation : '), c.fix) : null)));
}
