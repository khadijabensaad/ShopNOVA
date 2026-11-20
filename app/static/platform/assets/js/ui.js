// Bibliothèque de composants de la plateforme. Règle de sécurité : aucun contenu dynamique n'est injecté via
// innerHTML — tout passe par textContent / createElement (les sorties du modèle et des preuves sont du texte).

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'value') el.value = v;
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}
export const $ = (s, root = document) => root.querySelector(s);
export const $$ = (s, root = document) => [...root.querySelectorAll(s)];
export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
export function mount(el, ...children) { clear(el); append(el, children); return el; }

// ------------------------------------------------------------------ icônes (traits 24x24, dessinées pour le projet)
const P = {
  grid: 'M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z',
  bot: 'M12 8V4M8 4h8M5 8h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2zM9 13v1M15 13v1M1 13h2M21 13h2',
  brain: 'M9 3a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 2 5 3 3 0 0 0 6 2V5a2 2 0 0 0-3-2zM15 3a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-2 5 3 3 0 0 1-6 2M12 9h3M12 14h4',
  db: 'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4',
  network: 'M5 5h4v4H5zM15 5h4v4h-4zM10 15h4v4h-4zM7 9v2a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9M12 13v2',
  bug: 'M8 9a4 4 0 0 1 8 0v6a4 4 0 0 1-8 0zM12 9v10M4 13h4M16 13h4M5 7l3 2M19 7l-3 2M5 19l3-2M19 19l-3-2M9 4l1.5 2M15 4l-1.5 2',
  file: 'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6M9 15l2 2 4-4',
  clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2',
  flag: 'M5 21V4M5 4h11l-2 4 2 4H5',
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  report: 'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6M8 13h8M8 17h5',
  gear: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3',
  bell: 'M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0',
  sun: 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4',
  moon: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z',
  chevron: 'M9 18l6-6-6-6',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  play: 'M6 4l14 8-14 8z',
  refresh: 'M21 12a9 9 0 1 1-2.6-6.4M21 3v6h-6',
  x: 'M18 6L6 18M6 6l12 12',
  check: 'M20 6L9 17l-5-5',
  alert: 'M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01',
  info: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01',
  lock: 'M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4',
  download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3',
  external: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3',
  panel: 'M3 3h18v18H3zM9 3v18',
  menu: 'M3 6h18M3 12h18M3 18h18',
  tool: 'M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.5-2.5z',
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  layers: 'M12 2l10 5-10 5L2 7zM2 17l10 5 10-5M2 12l10 5 10-5',
  eye: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  hash: 'M4 9h16M4 15h16M10 3L8 21M16 3l-2 18',
  terminal: 'M4 17l6-6-6-6M12 19h8',
  zap: 'M13 2L3 14h9l-1 8 10-12h-9z',
};
export function icon(name, cls = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none'); svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8'); svg.setAttribute('stroke-linecap', 'round'); svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true'); if (cls) svg.setAttribute('class', cls);
  const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', P[name] || P.info); svg.append(p);
  return svg;
}
export const TEAM_ICON = { AGT: 'bot', LLM: 'brain', RAG: 'db', BLUE: 'shield' };

// ------------------------------------------------------------------ formatage
export const SEV = { critical: 'Critique', high: 'Élevée', medium: 'Moyenne', low: 'Faible' };
export const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
export const STATUS_LABEL = { OPEN: 'OPEN', ANALYZED: 'ANALYZED', MITIGATION_IN_PROGRESS: 'MITIGATION', FIXED: 'FIXED', RETEST_REQUIRED: 'RETEST REQUIRED', VERIFIED: 'VERIFIED' };
export function fmtTime(ts) { if (!ts) return '—'; const d = new Date(ts * 1000); return d.toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
export function ago(ts) {
  if (!ts) return '—'; const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `il y a ${Math.round(s)} s`; if (s < 3600) return `il y a ${Math.round(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.round(s / 3600)} h`; return `il y a ${Math.round(s / 86400)} j`;
}
export function pct(v) { return v === null || v === undefined ? '—' : `${v} %`; }

// ------------------------------------------------------------------ petits composants
export function badge(text, cls = 'neutral', ic) { return h('span', { class: `badge ${cls}` }, ic ? icon(ic) : null, text); }
export function sevBadge(s) { return h('span', { class: `badge b-${s}` }, h('span', { class: 'sev-dot', style: { background: 'currentColor' } }), SEV[s] || s); }
export function statusBadge(s) { return h('span', { class: `status st-${s}` }, STATUS_LABEL[s] || s); }
export function teamPill(team, meta) {
  const t = meta?.teams?.[team];
  const num = team === 'BLUE' ? 'BT' : t?.number || '';
  return h('span', { class: 'team-pill', 'data-team': team }, h('span', { class: 'num' }, num), team === 'BLUE' ? 'Blue Team' : (t?.short || team));
}
export function outcomeBadge(e) {
  if (e.status === 'unavailable') return badge('Indisponible', 'b-low', 'info');
  if (e.status === 'error') return badge('Erreur', 'b-warning', 'alert');
  return ({
    attack_succeeded: badge('Attaque réussie', 'b-danger', 'alert'),
    attack_blocked: badge('Bloquée', 'b-success', 'shield'),
    benign_ok: badge('Légitime · OK', 'b-info', 'check'),
    benign_blocked: badge('Légitime · bloqué', 'b-warning', 'alert'),
  })[e.outcome] || badge(e.kind === 'adhoc' ? 'Test libre' : '—', 'neutral');
}
export function modeBadge(m) { return m === 'hardened' ? badge('Durci', 'b-success', 'lock') : badge('Vulnérable', 'b-danger', 'target'); }
export function empty(ic, title, text, action) {
  return h('div', { class: 'empty' }, h('div', { class: 'em-ic' }, ic === 'nova' ? nova(64) : icon(ic)), h('h4', {}, title), text ? h('p', {}, text) : null, action || null);
}
export function skeleton(height = 120) { return h('div', { class: 'skeleton', style: { height: `${height}px` } }); }
export function errorBox(msg) { return h('div', { class: 'error-box' }, msg); }
export function card(title, sub, body, right) {
  return h('div', { class: 'card' },
    title ? h('div', { class: 'card-head' }, h('h3', {}, title), sub ? h('span', { class: 'sub' }, sub) : null, right ? h('div', { class: 'right' }, right) : null) : null,
    body);
}
export function seg(options, value, onChange, extraCls = {}) {
  const wrap = h('div', { class: 'seg', role: 'radiogroup' });
  const render = (v) => {
    clear(wrap);
    for (const [val, label] of options) {
      wrap.append(h('button', { type: 'button', role: 'radio', 'aria-checked': String(v === val), class: `${v === val ? 'on' : ''} ${extraCls[val] || ''}`,
        onclick: () => { render(val); onChange(val); } }, label));
    }
  };
  render(value);
  return wrap;
}
export function tabs(items, active, onChange) {
  const bar = h('div', { class: 'tabs', role: 'tablist' });
  for (const [id, label, n] of items) {
    bar.append(h('button', { class: `tab ${id === active ? 'on' : ''}`, role: 'tab', 'aria-selected': String(id === active),
      onclick: () => onChange(id) }, label, n !== undefined && n !== null ? h('span', { class: 'n' }, n) : null));
  }
  return bar;
}
export function code(obj) { return h('pre', { class: 'code' }, typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2)); }

// ------------------------------------------------------------------ toasts, modales, tiroirs, tooltips
let toastBox;
export function toast(msg, kind = 'ok') {
  if (!toastBox) { toastBox = h('div', { class: 'toasts', 'aria-live': 'polite' }); document.body.append(toastBox); }
  const t = h('div', { class: `toast ${kind}`, role: 'status' }, icon({ ok: 'check', err: 'alert', warn: 'alert', info: 'info' }[kind] || 'info'), h('div', {}, msg));
  toastBox.append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 6000 : 3800);
}
export function modal(title, body, actions = [], { size = '' } = {}) {
  const prev = document.activeElement;
  const close = () => { ov.remove(); document.removeEventListener('keydown', onKey); prev?.focus?.(); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const ov = h('div', { class: 'overlay', onclick: (e) => { if (e.target === ov) close(); } },
    h('div', { class: `modal ${size}`, role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('div', { class: 'modal-head' }, h('h3', {}, title), h('button', { class: 'icon-btn', 'aria-label': 'Fermer', onclick: close }, icon('x'))),
      h('div', { class: 'modal-body' }, body),
      actions.length ? h('div', { class: 'modal-foot' }, actions.map((a) => h('button', { class: `btn ${a.cls || ''}`, onclick: async (ev) => {
        if (a.onClick) { const btn = ev.currentTarget; btn.classList.add('busy'); try { const r = await a.onClick(); if (r !== false) close(); } finally { btn.classList.remove('busy'); } } else close();
      } }, a.label))) : null));
  document.body.append(ov); document.addEventListener('keydown', onKey);
  setTimeout(() => ov.querySelector('.modal-foot .btn.primary, .modal-foot .btn.danger, .modal-head .icon-btn')?.focus(), 30);
  return { close, el: ov };
}
export function confirmDialog(title, text, label = 'Confirmer', cls = 'primary') {
  return new Promise((resolve) => {
    let done = false;
    const m = modal(title, h('p', { style: { margin: 0 } }, text), [
      { label: 'Annuler', onClick: () => { done = true; resolve(false); } },
      { label, cls, onClick: () => { done = true; resolve(true); } },
    ], { size: 'sm' });
    const obs = new MutationObserver(() => { if (!document.body.contains(m.el)) { obs.disconnect(); if (!done) resolve(false); } });
    obs.observe(document.body, { childList: true });
  });
}
export function drawer(contentFn) {
  const prev = document.activeElement;
  const close = () => { wrap.remove(); document.removeEventListener('keydown', onKey); prev?.focus?.(); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const panel = h('div', { class: 'drawer', role: 'dialog', 'aria-modal': 'true' });
  const wrap = h('div', { class: 'drawer-wrap', onclick: (e) => { if (e.target === wrap) close(); } }, panel);
  document.body.append(wrap); document.addEventListener('keydown', onKey);
  contentFn(panel, close);
  return { close, panel };
}
let tip;
export function showTip(x, y, title, text) {
  if (!tip) { tip = h('div', { class: 'tooltip', role: 'tooltip' }); document.body.append(tip); }
  mount(tip, title ? h('b', {}, title) : null, text || '');
  tip.style.display = 'block';
  const r = tip.getBoundingClientRect();
  tip.style.left = `${Math.min(window.innerWidth - r.width - 8, x + 14)}px`;
  tip.style.top = `${Math.min(window.innerHeight - r.height - 8, y + 14)}px`;
}
export function hideTip() { if (tip) tip.style.display = 'none'; }
export function withTip(el, title, text) {
  el.addEventListener('mousemove', (e) => showTip(e.clientX, e.clientY, title, text));
  el.addEventListener('mouseleave', hideTip);
  el.addEventListener('focus', () => { const r = el.getBoundingClientRect(); showTip(r.left, r.bottom, title, text); });
  el.addEventListener('blur', hideTip);
  return el;
}

// ------------------------------------------------------------------ tableau de données (tri, recherche, pagination)
export function dataTable({ columns, rows, pageSize = 10, onRowClick, emptyState, initialSort }) {
  let sort = initialSort || null, page = 0;
  const root = h('div', {});
  const render = () => {
    let data = [...rows];
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      const val = col?.sortValue || ((r) => r[sort.key]);
      data.sort((a, b) => { const x = val(a), y = val(b); return (x > y ? 1 : x < y ? -1 : 0) * (sort.dir === 'asc' ? 1 : -1); });
    }
    const pages = Math.max(1, Math.ceil(data.length / pageSize));
    page = Math.min(page, pages - 1);
    const slice = data.slice(page * pageSize, page * pageSize + pageSize);
    const thead = h('tr', {}, columns.map((c) => {
      const th = h('th', { class: `${c.sortable === false ? '' : 'sortable'} ${c.num ? 'num' : ''}`, scope: 'col' }, c.label,
        sort?.key === c.key ? h('span', { class: 'arrow' }, sort.dir === 'asc' ? '↑' : '↓') : null);
      if (c.sortable !== false) th.addEventListener('click', () => { sort = { key: c.key, dir: sort?.key === c.key && sort.dir === 'desc' ? 'asc' : 'desc' }; render(); });
      return th;
    }));
    const tbody = h('tbody', {}, slice.map((r) => h('tr', { class: onRowClick ? 'click' : '', tabindex: onRowClick ? '0' : null,
      onclick: onRowClick ? () => onRowClick(r) : null, onkeydown: onRowClick ? (e) => { if (e.key === 'Enter') onRowClick(r); } : null },
    columns.map((c) => h('td', { class: `${c.num ? 'num' : ''} ${c.cls || ''}` }, c.render ? c.render(r) : (r[c.key] ?? '—'))))));
    mount(root,
      data.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, thead), tbody)) : (emptyState || empty('search', 'Aucun résultat', 'Aucun élément ne correspond aux filtres.')),
      data.length > pageSize ? h('div', { class: 'pager' }, `${page * pageSize + 1}–${Math.min(data.length, (page + 1) * pageSize)} sur ${data.length}`,
        h('button', { class: 'btn sm', disabled: page === 0, onclick: () => { page--; render(); } }, 'Précédent'),
        h('button', { class: 'btn sm', disabled: page >= pages - 1, onclick: () => { page++; render(); } }, 'Suivant')) : null);
  };
  render();
  root.update = (newRows) => { rows = newRows; page = 0; render(); };
  return root;
}

export function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
export function prefersReducedMotion() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches || document.documentElement.classList.contains('reduce-motion');
}

// ------------------------------------------------------------------ Nova, la mascotte de la v1 (même dessin)
export function nova(size = 34, cls = '') {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 100 100'); svg.setAttribute('width', size); svg.setAttribute('height', size);
  svg.setAttribute('class', `nova ${cls}`); svg.setAttribute('aria-hidden', 'true');
  const add = (tag, attrs) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); svg.append(e); return e; };
  add('line', { x1: 50, y1: 22, x2: 50, y2: 10, stroke: '#7c6cf0', 'stroke-width': 3, 'stroke-linecap': 'round' });
  add('circle', { cx: 50, cy: 8, r: 5.5, fill: '#7fb2ff' });
  add('rect', { x: 30, y: 78, width: 40, height: 16, rx: 8, fill: '#c9c2ff' });
  add('circle', { cx: 11, cy: 50, r: 8, fill: '#c9c2ff' });
  add('circle', { cx: 89, cy: 50, r: 8, fill: '#c9c2ff' });
  add('rect', { x: 13, y: 22, width: 74, height: 58, rx: 28, fill: '#fff', stroke: '#7c6cf0', 'stroke-width': 3 });
  add('rect', { x: 23, y: 32, width: 54, height: 38, rx: 19, fill: '#2d2a5e' });
  add('ellipse', { class: 'eye', cx: 39, cy: 49, rx: 5, ry: 7, fill: '#8fe3ff' });
  add('ellipse', { class: 'eye', cx: 61, cy: 49, rx: 5, ry: 7, fill: '#8fe3ff' });
  add('path', { d: 'M44 58q6 6 12 0', stroke: '#8fe3ff', 'stroke-width': 3, fill: 'none', 'stroke-linecap': 'round' });
  return svg;
}
