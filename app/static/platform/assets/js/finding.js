// Fiche détaillée d'un finding (tiroir) : cycle de vie, actions Blue Team, retest par l'équipe responsable,
// historique, exécutions et preuves. Les boutons n'apparaissent que si le serveur accorde la permission.
import { api } from './api.js';
import { h, icon, mount, drawer, toast, sevBadge, statusBadge, teamPill, fmtTime, badge, outcomeBadge, modeBadge, code, modal, confirmDialog, clear } from './ui.js';
import { app, notifyChanged } from './main.js';

const FLOW = ['OPEN', 'ANALYZED', 'MITIGATION_IN_PROGRESS', 'FIXED', 'RETEST_REQUIRED', 'VERIFIED'];
const NEXT = { OPEN: ['ANALYZED'], ANALYZED: ['MITIGATION_IN_PROGRESS', 'OPEN'], MITIGATION_IN_PROGRESS: ['FIXED', 'ANALYZED'],
  FIXED: ['RETEST_REQUIRED', 'MITIGATION_IN_PROGRESS'], RETEST_REQUIRED: ['MITIGATION_IN_PROGRESS'], VERIFIED: [] };
const ACTION_LABEL = { ANALYZED: 'Marquer comme analysé', MITIGATION_IN_PROGRESS: 'Démarrer la mitigation', FIXED: 'Correctif déployé (FIXED)',
  RETEST_REQUIRED: 'Demander le retest', OPEN: 'Rouvrir' };

export function stepper(status) {
  const idx = FLOW.indexOf(status);
  return h('div', { class: 'stepper', 'aria-label': `Statut : ${status}` }, FLOW.map((s, i) => h('div', {
    class: `step ${i < idx ? 'done' : ''} ${i === idx ? (s === 'VERIFIED' ? 'cur verified' : 'cur') : ''}` }, h('i'), s.replace('MITIGATION_IN_PROGRESS', 'MITIGATION').replace('RETEST_REQUIRED', 'RETEST').replace('_', ' '))));
}

export async function openEvidence(id) {
  const { evidence: e, integrity } = await api.get(`/evidence/${id}`);
  modal(`Preuve ${e.id}`, h('div', {},
    h('dl', { class: 'kv' },
      h('dt', {}, 'Exécution'), h('dd', { class: 'mono' }, e.execution_id),
      h('dt', {}, 'Finding'), h('dd', { class: 'mono' }, e.finding_id || '—'),
      h('dt', {}, 'Équipe / composant'), h('dd', {}, teamPill(e.team, app.meta), ' ', e.component),
      h('dt', {}, 'Scénario'), h('dd', { class: 'mono' }, e.scenario_id),
      h('dt', {}, 'Type · mode'), h('dd', {}, badge(e.type), ' ', modeBadge(e.mode), ' ', badge(e.kind)),
      h('dt', {}, 'Horodatage'), h('dd', {}, fmtTime(e.created_at)),
      h('dt', {}, 'Secrets détectés'), h('dd', {}, e.flags_detected?.length ? e.flags_detected.map((f) => badge(f, 'b-danger', 'lock')) : 'aucun'),
      h('dt', {}, 'SHA-256'), h('dd', { class: 'mono', style: { fontSize: '11.5px' } }, e.sha256),
      h('dt', {}, 'Intégrité'), h('dd', {}, integrity === 'valid' ? badge('Hachage vérifié', 'b-success', 'check') : badge('Altérée', 'b-danger', 'alert'))),
    h('div', { class: 'note', style: { margin: '14px 0 8px' } }, 'Contenu enregistré par le moteur au moment de l\'exécution. Les secrets sont masqués (FLAG{•••}) ; leur présence est indiquée ci-dessus.'),
    code(e.content)), [{ label: 'Fermer' }]);
}

export function openFinding(id, onChange) {
  drawer(async (panel, close) => {
    const load = async () => {
      mount(panel, h('div', { class: 'drawer-body' }, h('div', { class: 'skeleton', style: { height: '300px' } })));
      let d;
      try { d = await api.get(`/findings/${id}`); } catch (e) { mount(panel, h('div', { class: 'drawer-body' }, h('div', { class: 'error-box' }, e.message))); return; }
      const f = d.finding, perm = d.permissions;
      const refresh = async () => { await load(); onChange?.(); notifyChanged(); };
      const actions = h('div', { style: { display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '12px' } });
      if (perm.triage) {
        for (const to of NEXT[f.status]) {
          actions.append(h('button', { class: `btn ${to === 'OPEN' ? 'ghost' : 'primary'} sm`, onclick: async (ev) => {
            ev.currentTarget.classList.add('busy');
            try { await api.post(`/findings/${f.id}/transition`, { to, note: '' }); toast(`${f.id} → ${to}`); await refresh(); }
            catch (e) { toast(e.message, 'err'); ev.currentTarget?.classList.remove('busy'); }
          } }, ACTION_LABEL[to] || to));
        }
      }
      if (perm.retest && f.status === 'RETEST_REQUIRED') {
        actions.append(h('button', { class: 'btn success sm', onclick: async (ev) => {
          const b = ev.currentTarget; b.classList.add('busy');
          try {
            const r = await api.post(`/findings/${f.id}/retest`);
            toast(r.execution.outcome === 'attack_blocked' ? `Retest réussi : ${f.id} VERIFIED` : `Retest échoué : l'attaque réussit encore (${f.id})`, r.execution.outcome === 'attack_blocked' ? 'ok' : 'warn');
            await refresh();
          } catch (e) { toast(e.message, 'err'); b.classList.remove('busy'); }
        } }, icon('refresh'), 'Lancer le retest (mode durci)'));
      }
      if (!actions.childElementCount) {
        actions.append(h('span', { class: 'faint', style: { fontSize: '12.5px' } },
          f.status === 'VERIFIED' ? 'Correctif vérifié par retest. Aucune action requise.'
            : f.status === 'RETEST_REQUIRED' ? `En attente du retest par ${app.meta.teams[f.team].name}.` : 'Actions de remédiation réservées à la Blue Team.'));
      }
      const ownerIn = h('input', { class: 'input', value: f.owner || '', placeholder: 'Non assigné', disabled: !perm.triage, 'aria-label': 'Responsable' });
      const mitIn = h('textarea', { class: 'textarea', rows: 3, disabled: !perm.triage, style: { fontFamily: 'var(--font-sans)' }, 'aria-label': 'Mitigation' }, f.mitigation || '');
      const impactIn = h('textarea', { class: 'textarea', rows: 2, disabled: !perm.edit, style: { fontFamily: 'var(--font-sans)' }, 'aria-label': 'Impact' }, f.impact || '');
      const saveBtn = (perm.triage || perm.edit) ? h('button', { class: 'btn sm', onclick: async () => {
        const body = {};
        if (perm.triage) { body.owner = ownerIn.value; body.mitigation = mitIn.value; }
        if (perm.edit) body.impact = impactIn.value;
        try { await api.patch(`/findings/${f.id}`, body); toast('Finding mis à jour'); await refresh(); } catch (e) { toast(e.message, 'err'); }
      } }, 'Enregistrer') : null;
      const refs = f.refs || {};
      mount(panel,
        h('div', { class: 'drawer-head' },
          h('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' } }, h('span', { class: 'mono', style: { fontWeight: 700 } }, f.id),
            teamPill(f.team, app.meta), sevBadge(f.severity), statusBadge(f.status),
            h('button', { class: 'icon-btn', style: { marginLeft: 'auto' }, 'aria-label': 'Fermer', onclick: close }, icon('x'))),
          h('h3', { style: { fontSize: '19px', margin: '10px 0 4px' } }, f.title),
          h('div', { class: 'muted', style: { fontSize: '13px' } }, `${f.category} · ${f.component}`),
          stepper(f.status), actions),
        h('div', { class: 'drawer-body' },
          h('dl', { class: 'kv' },
            h('dt', {}, 'Description'), h('dd', {}, f.description),
            h('dt', {}, 'Impact'), h('dd', {}, impactIn),
            h('dt', {}, 'Détection'), h('dd', {}, f.detection_status === 'detected' ? badge('Détectée par la surveillance', 'b-success', 'eye') : badge('Non détectée', 'b-warning', 'alert')),
            h('dt', {}, 'Retest'), h('dd', {}, f.retest_result ? badge(f.retest_result, f.retest_result === 'pass' ? 'b-success' : f.retest_result === 'fail' ? 'b-danger' : 'b-info') : '—'),
            h('dt', {}, 'Responsable'), h('dd', {}, ownerIn),
            h('dt', {}, 'Mitigation'), h('dd', {}, mitIn),
            h('dt', {}, 'Équipes associées'), h('dd', {}, f.collaborating_teams?.length ? f.collaborating_teams.map((t) => teamPill(t, app.meta)) : '—',
              f.incident_id ? h('a', { href: '#/cross', style: { marginLeft: '8px' } }, `Incident ${f.incident_id}`) : null),
            h('dt', {}, 'Références'), h('dd', { style: { display: 'flex', gap: '6px', flexWrap: 'wrap' } },
              [...(refs.owasp || []).map((x) => badge(x, 'b-primary')), ...(refs.atlas || []).map((x) => badge(x, 'b-info')),
                ...(refs.controls || []).map((x) => badge(x, 'b-success', 'shield'))]),
            h('dt', {}, 'Compatibilité CTF'), h('dd', {}, `Défis ${(refs.legacy_challenges || []).join(', ') || '—'} · registre ${(refs.vuln_refs || []).join(', ') || '—'}`),
            h('dt', {}, 'Créé / mis à jour'), h('dd', {}, `${fmtTime(f.created_at)} · ${fmtTime(f.updated_at)}`)),
          saveBtn ? h('div', { style: { marginTop: '12px' } }, saveBtn) : null,
          h('h4', { style: { margin: '24px 0 10px' } }, 'Historique du cycle de vie'),
          h('div', { class: 'timeline' }, d.history.map((x) => h('div', { class: 'tl-item' }, h('div', { class: 'when' }, `${fmtTime(x.at)} · ${x.username || 'système'}`),
            h('div', {}, x.from_status ? `${x.from_status} → ${x.to_status}` : x.to_status), x.note ? h('div', { class: 'muted' }, x.note) : null))),
          perm.evidence ? h('div', {},
            h('h4', { style: { margin: '24px 0 10px' } }, 'Exécutions du scénario'),
            h('div', { class: 'card' }, h('div', { class: 'list' }, d.executions.map((e) => h('div', { class: 'li' },
              h('div', { class: 'li-main' }, h('div', { class: 'li-title' }, h('span', { class: 'mono' }, e.id), ' ', modeBadge(e.mode), ' ', badge(e.kind)), h('div', { class: 'li-sub' }, e.summary)),
              outcomeBadge(e), e.evidence_id ? h('button', { class: 'btn sm ghost', onclick: () => openEvidence(e.evidence_id) }, 'Preuve') : null))))) :
            h('div', { class: 'note', style: { marginTop: '18px' } }, 'Les exécutions et preuves détaillées sont réservées à l\'équipe responsable, à la Blue Team et aux auditeurs.')));
    };
    await load();
  });
}
export { confirmDialog, clear };
