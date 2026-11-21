// Espace WS4 (onglet de la Team 03) : Adversarial ML · Model Supply Chain · RAG & Vector Security.
// Réutilise les composants existants (cartes, badges, tableaux, seg, résultats de scénario) ; aucune nouvelle page.
import { api } from '../api.js';
import { h, icon, mount, card, seg, badge, toast, code, outcomeBadge, dataTable, errorBox } from '../ui.js';
import { notifyChanged } from '../main.js';
import { openEvidence } from '../finding.js';

const SAMPLE_MODEL = JSON.stringify({
  name: 'ws4-moderation-custom', version: '1.0', bias: -1.0,
  weights: { ignore: 3.0, instructions: 2.5, révèle: 2.5, 'injection-payload-x7': 5.0, confortable: -0.4, qualité: -0.4 },
  provenance: { supplier: 'ShopNOVA', source: 'équipe data', created: '2026-11' },
}, null, 2);
const STEP_LABEL = { pass: ['OK', 'b-success'], fail: ['Échec', 'b-danger'], warn: ['Attention', 'b-warning'] };
const DECISION = { kept: ['Transmis au LLM', 'b-warning'], filtered: ['Écarté', 'b-success'] };

function stepBadge(st) { const [t, c] = STEP_LABEL[st] || [st, 'neutral']; return badge(t, c); }

function checksTable(steps) {
  return h('div', { class: 'list card', style: { marginTop: '10px' } }, steps.map((c) => h('div', { class: 'li', style: { padding: '9px 14px' } },
    h('div', { class: 'li-main' }, h('div', { class: 'li-title' }, c.label), h('div', { class: 'li-sub' }, c.detail)), stepBadge(c.status))));
}

function cycle(items) { // visualisation légère et linéaire (réutilise .stage)
  return h('div', { class: 'ws4-flow', role: 'list' }, items.map(([t, sub, st], i) => [
    h('div', { class: `stage ws4-step ${st || ''}`, role: 'listitem' }, h('div', { class: 'n' }, String(i + 1).padStart(2, '0')),
      h('div', { style: { fontWeight: 700, fontSize: '13px' } }, t), sub ? h('div', { class: 'faint', style: { fontSize: '11.5px' } }, sub) : null),
    i < items.length - 1 ? h('span', { class: 'ws4-arrow', 'aria-hidden': 'true' }, '→') : null]));
}

function lastResult(r) {
  if (!r) return h('span', { class: 'faint' }, 'pas encore exécuté');
  return outcomeBadge({ outcome: r.outcome, status: 'completed' });
}

// ------------------------------------------------------------------ 1. Adversarial ML
function adversarialSection(ov, sc, ctx) {
  const byId = Object.fromEntries(sc.map((s) => [s.id, s]));
  return h('div', {},
    h('div', { class: 'section-title' }, h('h2', {}, 'Adversarial ML'), h('span', { class: 'muted' }, 'attaques du modèle de modération, démontrées par les défis B1 à B5')),
    card('Cycle observé', 'chaque attaque vise une étape ; la Blue Team surveille la dernière',
      h('div', { class: 'card-body' }, cycle([['Input', 'avis client'], ['Model', 'classificateur WS4'], ['Prediction', 'sûr / malveillant'], ['Attack / Detection', 'DET-ML-01 · contrôles CTL-RAG', 'accent']]))),
    h('div', { class: 'grid g-2 mt' }, ov.adversarial.map((a) => {
      const s = byId[a.scenarios[0]];
      return card(a.name, a.demo, h('div', { class: 'card-body' },
        h('dl', { class: 'kv' },
          h('dt', {}, 'Objectif'), h('dd', {}, a.objective),
          h('dt', {}, 'Principe'), h('dd', {}, a.principle),
          h('dt', {}, 'Composant ciblé'), h('dd', {}, badge(a.component, 'b-primary')),
          h('dt', {}, 'Résultat'), h('dd', { style: { display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' } },
            h('span', { class: 'faint' }, 'vulnérable'), lastResult(a.results.vulnerable), h('span', { class: 'faint' }, 'durci'), lastResult(a.results.hardened)),
          h('dt', {}, 'Contre-mesure'), h('dd', {}, a.countermeasure, ' ', badge(a.control, 'b-success', 'shield'))),
        s && ctx.canRun ? h('div', { style: { display: 'flex', gap: '8px', marginTop: '14px' } },
          h('button', { class: 'btn sm', onclick: (e) => ctx.runScenario(ctx.app, s, 'vulnerable', e.currentTarget, ctx.reload) }, icon('play'), 'Démontrer (vulnérable)'),
          h('button', { class: 'btn sm', onclick: (e) => ctx.runScenario(ctx.app, s, 'hardened', e.currentTarget, ctx.reload) }, icon('lock'), 'Rejouer (durci)')) : null));
    })));
}

// ------------------------------------------------------------------ 2. Model Supply Chain
function supplyChainSection(ov, ctx) {
  const st = ov.supply_chain;
  let mode = 'hardened';
  const out = h('div', {}, h('div', { class: 'card' }, h('div', { class: 'card-body muted' }, 'Le rapport du scanner, l\'état de signature et le résultat de vérification s\'affichent ici. Chaque opération produit une preuve hachée consultable par la Blue Team.')));
  const file = h('input', { type: 'file', class: 'input', accept: '.json,.pkl,.pt,.bin,.onnx,.gguf,.safetensors', 'aria-label': 'Fichier de modèle' });
  const text = h('textarea', { class: 'textarea mono', rows: 9, 'aria-label': 'Modèle JSON', style: { fontSize: '12px' } }, SAMPLE_MODEL);
  const sig = st.custom?.signature;
  const steps = [
    ['Upload', st.custom ? 'fichier importé' : 'aucun fichier', st.custom ? 'done' : ''],
    ['Security Scan', ov._scan ? ov._scan.verdict : (st.custom ? 'voir résultat' : '—'), ov._scan ? (ov._scan.verdict === 'accepted' ? 'done' : 'bad') : ''],
    ['AI-BOM', 'inventaire CycloneDX 1.7', 'done'],
    ['Sign', sig ? (sig.mode === 'sigstore' ? 'Sigstore' : 'démo locale') : 'non signé', sig ? 'done' : ''],
    ['Verify', st.custom ? (st.custom.matches_activated ? 'empreinte vérifiée' : 'à vérifier') : '—', st.custom?.matches_activated ? 'done' : ''],
    ['Activate', `actif : ${st.active}`, st.active === 'custom' ? 'done' : '']];

  const show = (title, r, render) => {
    mount(out, h('div', { class: 'card' }, h('div', { class: 'card-body' },
      h('div', { style: { display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '6px' } }, h('b', {}, title),
        r.detections?.length ? badge(`${r.detections.length} détection(s)`, 'b-warning', 'eye') : badge('Aucune détection', 'neutral'),
        r.evidence_id ? h('button', { class: 'btn sm', style: { marginLeft: 'auto' }, onclick: () => openEvidence(r.evidence_id) }, icon('file'), `Preuve ${r.evidence_id}`) : null),
      r.detections?.length ? h('div', { class: 'muted', style: { fontSize: '12.5px' } }, r.detections.map((d) => `${d.rule} — ${d.message}`).join(' · ')) : null,
      render(r.result))));
  };
  const call = async (btn, fn) => { btn.classList.add('busy'); try { await fn(); notifyChanged(); } catch (e) { toast(e.message, 'err'); } finally { btn.classList.remove('busy'); } };
  const readFile = () => new Promise((resolve, reject) => {
    const f = file.files[0]; if (!f) { resolve(null); return; }
    const rd = new FileReader(); rd.onload = () => resolve({ name: f.name, b64: rd.result.split(',')[1] || '' }); rd.onerror = reject; rd.readAsDataURL(f);
  });
  const scanView = (res) => h('div', {},
    res.error ? errorBox(res.error) : h('div', { class: 'note' }, res.status || 'Fichier stocké (mode vulnérable : rapport informatif, non bloquant).'),
    res.scan ? h('div', {}, h('div', { style: { display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '10px' } },
      badge(res.scan.verdict === 'accepted' ? 'Accepté par le scanner' : 'Rejeté par le scanner', res.scan.verdict === 'accepted' ? 'b-success' : 'b-danger', res.scan.verdict === 'accepted' ? 'check' : 'alert'),
      badge(`format détecté : ${res.scan.detected_format}`), badge(`${res.scan.size} octets`), h('span', { class: 'mono faint', style: { fontSize: '11.5px' } }, `SHA-256 ${res.scan.sha256.slice(0, 24)}…`)),
    checksTable(res.scan.checks),
    res.scan.pickle_static_analysis?.references?.length ? h('div', { class: 'note', style: { marginTop: '10px' } }, h('b', {}, 'Opcodes Pickle (lus, jamais exécutés) : '), (res.scan.pickle_static_analysis.references || []).join(', ') || '—') : null,
    h('p', { class: 'faint', style: { fontSize: '12px', margin: '10px 0 0' } }, res.scan.limits)) : null);
  const verifyView = (res) => {
    // /verify renvoie le contrôle complet ; /activate le place dans « verification » en cas de refus
    const v = res.verification && 'sha256' in res.verification ? res.verification : res;
    const steps = v.verification?.steps || [];
    return h('div', {}, res.error ? errorBox(res.error) : null,
      'verified' in v ? h('div', { style: { marginTop: '8px' } }, badge(v.verified ? 'Vérifié : activation autorisée' : 'Non vérifié : activation refusée', v.verified ? 'b-success' : 'b-danger', v.verified ? 'check' : 'lock'),
        v.verification?.warning ? h('div', { class: 'note', style: { marginTop: '8px' } }, v.verification.warning) : null,
        steps.length ? checksTable(steps) : h('div', { class: 'note', style: { marginTop: '8px' } }, v.scan ? 'Aucune signature à vérifier.' : 'Aucun modèle importé.')) : null,
      res.ok ? h('div', { class: 'note', style: { marginTop: '8px' } }, `Modèle actif : ${res.active}`) : null);
  };

  const canRun = ov.can_run;
  const actions = h('div', { style: { display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '10px' } },
    h('button', { class: 'btn primary', disabled: !canRun, onclick: (e) => call(e.currentTarget, async () => {
      const f = await readFile();
      const r = await api.post('/ws4/model/scan', f ? { filename: f.name, content_b64: f.b64, mode } : { filename: 'custom_model.json', content: text.value, mode });
      ov._scan = r.result.scan; show('Analyse du fichier', r, scanView);
    }) }, icon('search'), 'Importer et analyser'),
    h('button', { class: 'btn', disabled: !ov.can_sign, title: ov.can_sign ? 'Signer en tant qu\'éditeur de confiance' : 'Réservé à l\'administrateur (éditeur de confiance)', onclick: (e) => call(e.currentTarget, async () => {
      const r = await api.post('/ws4/model/sign', {});
      show('Signature', r, (res) => (res.error ? errorBox(res.error) : h('div', {}, h('div', { class: 'note' }, res.signature.warning), code({ mode: res.signature.mode, algorithm: res.signature.algorithm, identity: res.signature.identity, issuer: res.signature.issuer, artifact_sha256: res.signature.artifact_sha256 }))));
    }) }, icon('hash'), 'Signer'),
    h('button', { class: 'btn', onclick: (e) => call(e.currentTarget, async () => { show('Vérification avant activation', await api.post('/ws4/model/verify', {}), verifyView); }) }, icon('shield'), 'Vérifier'),
    h('button', { class: 'btn', disabled: !canRun, onclick: (e) => call(e.currentTarget, async () => { show('Activation', await api.post('/ws4/model/activate', { mode }), verifyView); }) }, icon('play'), 'Activer'),
    h('button', { class: 'btn ghost', disabled: !canRun, onclick: (e) => call(e.currentTarget, async () => { await api.post('/ws4/model/reset', {}); toast('Modèle officiel rétabli'); ctx.reload(); }) }, icon('refresh'), 'Rétablir l\'officiel'));

  const sigstore = st.sigstore;
  return h('div', {},
    h('div', { class: 'section-title' }, h('h2', {}, 'Model Supply Chain'), h('span', { class: 'muted' }, 'du fichier importé au modèle actif : analyser, inventorier, signer, vérifier, activer')),
    card('Pipeline', null, h('div', { class: 'card-body' }, cycle(steps),
      h('div', { style: { display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '12px' } },
        badge(`Signature locale : ${st.local_signing ? 'disponible (démo Ed25519, non Sigstore)' : 'indisponible'}`, st.local_signing ? 'b-info' : 'neutral'),
        badge(`Sigstore : ${sigstore.ready ? `configuré (${sigstore.identity})` : sigstore.installed ? 'installé, identité attendue non configurée' : 'non installé'}`, sigstore.ready ? 'b-success' : 'neutral'),
        h('span', { class: 'mono faint', style: { fontSize: '11.5px' } }, `officiel SHA-256 ${st.official_sha256.slice(0, 16)}…`)))),
    h('div', { class: 'grid g-2 mt' },
      card('Importer un modèle', 'JSON uniquement ; tout autre format est refusé sans être chargé', h('div', { class: 'card-body' },
        h('div', { class: 'form-row' }, h('div', { class: 'field' }, h('label', {}, 'Fichier (optionnel)'), file),
          h('div', { class: 'field', style: { flex: '0 0 auto' } }, h('label', {}, 'Cible'), seg([['vulnerable', 'Vulnérable'], ['hardened', 'Durci']], mode, (v) => { mode = v; }, { vulnerable: 'vuln', hardened: 'hard' }))),
        h('div', { class: 'field', style: { marginTop: '10px' } }, h('label', {}, 'ou contenu JSON'), text), actions)),
      out),
    h('div', { class: 'mt' }, ctx.inventory));
}

async function inventoryCard() {
  let inv;
  try { inv = await api.get('/ws4/aibom'); } catch (e) { return card('AI Supply Chain Inventory', null, h('div', { class: 'card-body' }, errorBox(e.message))); }
  const exportBtn = h('button', { class: 'btn sm', onclick: async () => {
    try {
      const res = await fetch('/api/secops/ws4/aibom/export', { credentials: 'same-origin' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const url = URL.createObjectURL(await res.blob()); const a = h('a', { href: url, download: 'shopnova-ai-bom.cdx.json' }); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } catch (e) { toast(`Export impossible : ${e.message}`, 'err'); }
  } }, icon('download'), 'Exporter (JSON CycloneDX)');
  const off = inv.official_validation;
  return card('AI Supply Chain Inventory', `CycloneDX ${inv.spec_version} · ${inv.components.length} composants · Ollama : ${inv.ollama}`,
    h('div', {},
      h('div', { class: 'card-body', style: { display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center', paddingBottom: '8px' } },
        badge(inv.validation.valid ? 'Validation locale : conforme' : 'Validation locale : erreurs', inv.validation.valid ? 'b-success' : 'b-danger', inv.validation.valid ? 'check' : 'alert'),
        badge(off.available ? (off.valid ? 'Schéma officiel : conforme' : 'Schéma officiel : non conforme') : 'Schéma officiel : vérifié en CI', off.available ? (off.valid ? 'b-success' : 'b-danger') : 'neutral'),
        badge(`${inv.validation.summary.with_unknown_fields} composant(s) avec champs inconnus`, inv.validation.summary.with_unknown_fields ? 'b-warning' : 'neutral'),
        h('span', { style: { marginLeft: 'auto' } }, exportBtn)),
      inv.validation.errors.length ? h('div', { class: 'card-body' }, errorBox(inv.validation.errors.join(' · '))) : null,
      dataTable({ rows: inv.components, pageSize: 8, columns: [
        { key: 'name', label: 'Composant', render: (c) => h('div', {}, h('div', { class: 'mono', style: { fontWeight: 600 } }, c.name), c.supplier ? h('div', { class: 'faint', style: { fontSize: '11.5px' } }, c.supplier) : null) },
        { key: 'type', label: 'Type', render: (c) => badge(c.type, c.type === 'machine-learning-model' ? 'b-primary' : c.type === 'data' ? 'b-info' : 'neutral') },
        { key: 'version', label: 'Version', render: (c) => (c.version ? h('span', { class: 'mono' }, c.version) : badge('inconnue', 'b-warning')) },
        { key: 'sha256', label: 'Intégrité', render: (c) => (c.sha256 ? h('span', { class: 'mono faint', style: { fontSize: '11px' } }, `SHA-256 ${c.sha256.slice(0, 12)}…`) : h('span', { class: 'faint' }, c.integrity || '—')) },
        { key: 'unknown', label: 'Champs inconnus', render: (c) => (c.unknown ? h('span', { class: 'muted', style: { fontSize: '12px' } }, c.unknown) : h('span', { class: 'faint' }, '—')) }] })));
}

// ------------------------------------------------------------------ 3. RAG & Vector Security
function vectorSection(sc, ctx) {
  let mode = 'vulnerable';
  const q = h('input', { class: 'input', value: 'Quelle est la garantie du casque audio ?', 'aria-label': 'Requête utilisateur' });
  const out = h('div', {});
  const run = h('button', { class: 'btn primary', disabled: !ctx.canRun, onclick: async () => {
    run.classList.add('busy');
    try {
      const r = await api.post('/ws4/rag/retrieve', { query: q.value, mode });
      const res = r.result;
      mount(out, h('div', { style: { marginTop: '12px' } },
        h('div', { style: { display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '8px' } },
          badge(`${res.decisions.length} extrait(s) récupéré(s)`), badge(`${res.order.length} transmis au LLM`, 'b-info'),
          r.detections.length ? badge(r.detections.map((d) => d.rule).join(' · '), 'b-warning', 'eye') : badge('Aucune détection', 'neutral'),
          h('button', { class: 'btn sm', style: { marginLeft: 'auto' }, onclick: () => openEvidence(r.evidence_id) }, icon('file'), `Preuve ${r.evidence_id}`)),
        dataTable({ rows: res.decisions, pageSize: 6, columns: [
          { key: 'rank', label: '#', num: true },
          { key: 'excerpt', label: 'Document', render: (d) => h('div', {}, h('div', { class: 'mono faint', style: { fontSize: '11px' } }, `${d.collection} · ${d.source || '?'}`), h('div', { style: { fontSize: '12.5px', maxWidth: '420px' } }, d.excerpt.slice(0, 140))) },
          { key: 'distance', label: 'Distance', num: true, render: (d) => (d.distance === null || d.distance === undefined ? '—' : d.distance) },
          { key: 'trust', label: 'Confiance', render: (d) => badge(d.trust || '?', d.trust === 'officiel' ? 'b-success' : 'b-warning') },
          { key: 'provenance', label: 'Provenance', render: (d) => h('div', {}, badge(d.provenance.valid ? 'valide' : 'invalide', d.provenance.valid ? 'b-success' : 'b-danger'), h('div', { class: 'faint', style: { fontSize: '11px' } }, d.provenance.reason)) },
          { key: 'decision', label: 'Décision', render: (d) => h('div', {}, badge(...DECISION[d.decision]), h('div', { class: 'faint', style: { fontSize: '11px' } }, d.reason)) }] }),
        h('div', { class: 'field', style: { marginTop: '10px' } }, h('label', {}, 'Contexte réellement transmis au LLM'), code(res.context || '(vide)'))));
    } catch (e) { mount(out, h('div', { style: { marginTop: '12px' } }, errorBox(e.message))); } finally { run.classList.remove('busy'); }
  } }, icon('search'), 'Inspecter la récupération');
  const scen = sc.filter((s) => ['RAG-S13', 'RAG-S14'].includes(s.id));
  return h('div', {},
    h('div', { class: 'section-title' }, h('h2', {}, 'RAG & Vector Security'), h('span', { class: 'muted' }, 'vraie récupération ChromaDB : score, confiance, provenance et contexte final')),
    h('div', { class: 'grid g-2' },
      card('Retrieval Inspector', 'politique de récupération appliquée en mode durci', h('div', { class: 'card-body' },
        h('div', { class: 'form-row' }, h('div', { class: 'field' }, h('label', {}, 'Requête utilisateur'), q),
          h('div', { class: 'field', style: { flex: '0 0 auto' } }, h('label', {}, 'Cible'), seg([['vulnerable', 'Vulnérable'], ['hardened', 'Durci']], mode, (v) => { mode = v; }, { vulnerable: 'vuln', hardened: 'hard' }))),
        h('div', { style: { marginTop: '10px' } }, run))),
      card('Scénarios', 'exécution réelle ; « indisponible » si ChromaDB ou les embeddings ne répondent pas', h('div', { class: 'list' }, scen.map((s) => h('div', { class: 'li' },
        h('div', { class: 'li-main' }, h('div', { class: 'li-title' }, `${s.id} · ${s.title}`), h('div', { class: 'li-sub' }, s.mitigation)),
        ctx.canRun ? h('div', { style: { display: 'flex', gap: '6px' } },
          h('button', { class: 'btn sm', title: 'Mode vulnérable', onclick: (e) => ctx.runScenario(ctx.app, s, 'vulnerable', e.currentTarget, ctx.reload) }, icon('play'), 'V'),
          h('button', { class: 'btn sm', title: 'Mode durci', onclick: (e) => ctx.runScenario(ctx.app, s, 'hardened', e.currentTarget, ctx.reload) }, icon('lock'), 'D')) : null))))),
    out);
}

export async function ws4Console({ app, sc, canRun, reload, runScenario }) {
  const [ov, inventory] = await Promise.all([api.get('/ws4/overview'), inventoryCard()]);
  const root = h('div', {});
  const ctx = { app, canRun, reload, runScenario, inventory };
  mount(root,
    h('div', { class: 'note' }, h('b', {}, 'Une seule histoire : '), 'attaquer un modèle → compromettre sa chaîne d\'approvisionnement → vérifier son intégrité → sécuriser son utilisation (RAG) → détecter et prouver. Chaque action est tracée par une preuve hachée.'),
    adversarialSection(ov, sc, ctx), supplyChainSection(ov, ctx), vectorSection(sc, ctx));
  return root;
}
