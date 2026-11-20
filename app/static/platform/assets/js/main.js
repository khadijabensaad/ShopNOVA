// Point d'entrée : authentification, coque applicative (barre latérale, barre supérieure), routage par hash.
import { api, ApiError } from './api.js';
import { h, icon, mount, clear, toast, TEAM_ICON, ago, $, hideTip, nova } from './ui.js';
import { Scene3D, quality } from './scene3d.js';

const PAGES = {
  overview: () => import('./pages/overview.js'),
  team: () => import('./pages/team.js'),
  blue: () => import('./pages/blue.js'),
  cross: () => import('./pages/cross.js'),
  registry: () => import('./pages/registry.js'),
  evidence: () => import('./pages/evidence.js'),
  history: () => import('./pages/history.js'),
  ctf: () => import('./pages/ctf.js'),
  monitoring: () => import('./pages/monitoring.js'),
  reports: () => import('./pages/reports.js'),
  settings: () => import('./pages/settings.js'),
};

export const app = {
  user: null, meta: null, health: null,
  can(perm) {
    const perms = this.user?.permissions || [];
    if (perms.includes('*') || perms.includes(perm)) return true;
    return perms.includes(`${perm.split(':')[0]}:*`);
  },
  navigate(path) { if (location.hash !== `#${path}`) location.hash = path; else route(); },
  setTheme(pref) {
    try { localStorage.setItem('snv-theme', pref); } catch { /* stockage indisponible */ }
    applyTheme(true);
  },
};

function applyTheme(animate) {
  let pref = 'system';
  try { pref = localStorage.getItem('snv-theme') || 'system'; } catch { /* */ }
  const dark = pref === 'dark' || (pref === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  const root = document.documentElement;
  if (animate) { root.classList.add('theme-anim'); setTimeout(() => root.classList.remove('theme-anim'), 300); }
  root.setAttribute('data-theme', dark ? 'dark' : 'light');
  window.dispatchEvent(new CustomEvent('snv:theme', { detail: dark ? 'dark' : 'light' }));
  const btn = $('#theme-btn'); if (btn) mount(btn, icon(dark ? 'sun' : 'moon'));
}
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => applyTheme(true));

// ------------------------------------------------------------------ navigation (onglets principaux + menu « Plus »)
function navModel() {
  const T = app.meta.teams;
  return {
    primary: [['overview', 'Command Center', 'grid', null, null],
      ...['AGT', 'LLM', 'RAG'].map((t) => [`team/${t}`, T[t].short, TEAM_ICON[t], `evidence:${t}`, t]),
      ['blue', 'Blue Team', 'shield', 'blue', 'BLUE'], ['cross', 'Cross-component', 'network', null, null], ['ctf', 'CTF', 'flag', null, null]],
    more: [['registry', 'Registre des vulnérabilités', 'bug', null], ['evidence', 'Preuves', 'file', 'evidence-any'], ['history', 'Historique des attaques', 'clock', 'evidence-any'],
      ['monitoring', 'Monitoring', 'activity', 'monitoring'], ['reports', 'Rapports', 'report', null], ['settings', 'Paramètres', 'gear', null]],
  };
}
function allowed(perm) {
  if (!perm) return true;
  if (perm === 'blue') return app.can('triage') || app.can('audit:read');
  if (perm === 'evidence-any') return ['AGT', 'LLM', 'RAG'].some((t) => app.can(`evidence:${t}`));
  return app.can(perm);
}

function brandMark() { return nova(36, 'brand-mark'); }

let shell, moreBtn;
function buildShell() {
  const { primary, more } = navModel();
  const tabs = h('nav', { class: 'navtabs', 'aria-label': 'Navigation principale' });
  for (const [path, text, ic, perm, team] of primary) {
    if (!allowed(perm)) continue;
    tabs.append(h('a', { class: 'navtab', href: `#/${path}`, 'data-path': path, 'data-team': team || null },
      h('span', { class: 'ic' }, icon(ic)), text, team && team !== 'BLUE' ? h('span', { class: 'num' }, app.meta.teams[team].number) : null));
  }
  const moreItems = more.filter((m) => allowed(m[3]));
  moreBtn = h('button', { class: 'navtab', 'aria-haspopup': 'true', 'data-more': '1' }, icon('menu'), 'Plus');
  const moreWrap = h('div', { style: { position: 'relative' } }, moreBtn);
  let pop;
  moreBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (pop) { pop.remove(); pop = null; return; }
    pop = h('div', { class: 'popover', role: 'menu', style: { left: 0, right: 'auto', minWidth: '250px', position: 'fixed',
      top: `${moreBtn.getBoundingClientRect().bottom + 8}px`, left: `${Math.min(moreBtn.getBoundingClientRect().left, window.innerWidth - 270)}px` } },
    moreItems.map(([path, text, ic]) => h('a', { class: 'pop-item', role: 'menuitem', href: `#/${path}` }, icon(ic), text)));
    document.body.append(pop);
  });
  document.addEventListener('click', () => { if (pop) { pop.remove(); pop = null; } });
  window.addEventListener('hashchange', () => { if (pop) { pop.remove(); pop = null; } });
  tabs.append(h('span', { class: 'navsep' }), moreWrap);
  const search = h('input', { class: 'input', type: 'search', placeholder: 'Rechercher…  ( / )', 'aria-label': 'Recherche globale', id: 'search' });
  const searchBox = h('div', { class: 'search' }, icon('search'), search);
  bindSearch(search, searchBox);
  const top = h('header', { class: 'topbar' }, h('div', { class: 'topbar-in' },
    h('div', { class: 'top-row' },
      h('a', { class: 'brand', href: '#/overview', 'aria-label': 'ShopNOVA — accueil' }, brandMark(),
        h('div', {}, h('div', { class: 'brand-name' }, 'SHOPNOVA'), h('div', { class: 'brand-sub' }, 'AI Security Lab'))),
      h('span', { class: 'chip ok', id: 'env-chip', title: 'Environnement local isolé (127.0.0.1)' }, h('i', { class: 'dot' }), 'local lab'),
      h('span', { class: 'chip off', id: 'llm-status', title: 'État du modèle local' }, h('i', { class: 'dot off' }), 'LLM …'),
      h('div', { class: 'spacer' }), searchBox, notifButton(),
      h('button', { class: 'icon-btn', id: 'theme-btn', 'aria-label': 'Changer de thème', onclick: () => {
        const dark = document.documentElement.getAttribute('data-theme') === 'dark'; app.setTheme(dark ? 'light' : 'dark');
      } }),
      userMenu()),
    tabs, h('div', { class: 'crumbs', id: 'crumbs' })));
  shell = h('div', { class: 'shell' }, top, h('main', { class: 'content', id: 'content', tabindex: '-1' }));
  mount(document.getElementById('app'), shell);
  applyTheme(false);
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) { e.preventDefault(); search.focus(); }
  });
  refreshHealth(); refreshNotifs();
  setInterval(refreshNotifs, 30000);
}

async function refreshHealth() {
  try {
    app.health = await api.get('/health');
    const el = $('#llm-status');
    el.className = `chip ${app.health.llm ? 'ok' : 'off'}`;
    mount(el, h('i', { class: `dot ${app.health.llm ? '' : 'off'}` }), app.health.llm ? `${app.meta.lab.model} en ligne` : 'LLM hors ligne');
    el.title = app.health.llm ? 'Ollama joignable : les scénarios « modèle réel » sont exécutables.'
      : 'Ollama injoignable : seuls les scénarios déterministes sont exécutables (aucun résultat n\'est simulé).';
  } catch { /* le bandeau reste en l'état */ }
}

// ------------------------------------------------------------------ notifications
let notifCount, notifPop;
function notifButton() {
  notifCount = h('span', { class: 'count', hidden: true });
  const btn = h('button', { class: 'icon-btn', 'aria-label': 'Notifications', 'aria-haspopup': 'true' }, icon('bell'), notifCount);
  const wrap = h('div', { style: { position: 'relative' } }, btn);
  btn.addEventListener('click', async (e) => {
    e.stopPropagation();
    if (notifPop) { notifPop.remove(); notifPop = null; return; }
    const { events } = await api.get('/events?limit=12');
    notifPop = h('div', { class: 'popover', role: 'menu' }, h('div', { class: 'pop-head' }, 'Événements de sécurité récents'),
      events.length ? events.map((ev) => h('div', { class: 'pop-item', onclick: () => app.navigate(app.can('monitoring') ? '/monitoring' : '/overview') },
        h('i', { class: 'ev-sev', style: { background: sevColor(ev.severity) } }),
        h('div', { style: { flex: 1, minWidth: 0 } }, h('div', { style: { fontWeight: 500 } }, ev.rule), h('div', { class: 'muted', style: { fontSize: '12px' } }, ev.message)),
        h('span', { class: 'faint mono', style: { fontSize: '11px' } }, ago(ev.at)))) : h('div', { class: 'pop-item muted' }, 'Aucun événement pour le moment.'));
    wrap.append(notifPop);
    localStorage.setItem('snv-notif-seen', String(Date.now() / 1000)); notifCount.hidden = true;
  });
  document.addEventListener('click', () => { if (notifPop) { notifPop.remove(); notifPop = null; } });
  return wrap;
}
export function sevColor(s) { return { critical: 'var(--critical)', high: 'var(--warning)', medium: 'var(--info)', low: 'var(--text-3)' }[s] || 'var(--text-3)'; }
async function refreshNotifs() {
  try {
    const { events } = await api.get('/events?limit=50');
    const seen = Number(localStorage.getItem('snv-notif-seen') || 0);
    const n = events.filter((e) => e.at > seen && ['critical', 'high'].includes(e.severity)).length;
    notifCount.textContent = n > 9 ? '9+' : String(n); notifCount.hidden = !n;
  } catch { /* */ }
}
export function notifyChanged() { refreshNotifs(); }

// ------------------------------------------------------------------ recherche globale
function bindSearch(input, box) {
  let pop, timer, results = [], sel = 0;
  const close = () => { pop?.remove(); pop = null; };
  const go = (r) => {
    close(); input.value = '';
    if (r.type === 'finding') app.navigate(`/registry?f=${r.id}`);
    else if (r.type === 'scenario') app.navigate(`/team/${r.team}?s=${r.id}`);
    else if (r.type === 'evidence') app.navigate(`/evidence?e=${r.id}`);
    else app.navigate(r.path);
  };
  const pages = () => { const m = navModel(); return [...m.primary, ...m.more].filter((i) => allowed(i[3])).map(([path, text]) => ({ type: 'page', label: text, path: `/${path}`, id: 'page' })); };
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const q = input.value.trim(); if (q.length < 2) { close(); return; }
      let server = [];
      try { server = (await api.get(`/search?q=${encodeURIComponent(q)}`)).results; } catch { /* */ }
      results = [...pages().filter((p) => p.label.toLowerCase().includes(q.toLowerCase())), ...server]; sel = 0;
      close();
      pop = h('div', { class: 'popover', role: 'listbox' }, results.length ? results.map((r, i) => h('div', { class: `pop-item ${i === 0 ? 'sel' : ''}`, role: 'option', onclick: () => go(r) },
        icon({ finding: 'bug', scenario: 'target', evidence: 'file', page: 'chevron' }[r.type]),
        h('div', { style: { flex: 1, minWidth: 0 } }, h('div', {}, r.label), h('div', { class: 'faint mono', style: { fontSize: '11px' } }, r.type === 'page' ? 'page' : `${r.type} · ${r.id}`)))) : h('div', { class: 'pop-item muted' }, 'Aucun résultat.'));
      box.append(pop);
    }, 180);
  });
  input.addEventListener('keydown', (e) => {
    if (!pop) return;
    const items = pop.querySelectorAll('.pop-item[role=option]');
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); sel = (sel + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length; items.forEach((it, i) => it.classList.toggle('sel', i === sel)); }
    if (e.key === 'Enter' && results[sel]) go(results[sel]);
    if (e.key === 'Escape') close();
  });
  input.addEventListener('blur', () => setTimeout(close, 200));
}

function userMenu() {
  const u = app.user;
  const initials = u.display_name.split(' ').map((w) => w[0]).join('').slice(0, 2).toUpperCase();
  const btn = h('button', { class: 'user-btn', 'aria-haspopup': 'true' }, h('span', { class: 'avatar' }, initials),
    h('span', { class: 'user-meta' }, h('b', {}, u.display_name), h('small', {}, u.role_label)));
  const wrap = h('div', { style: { position: 'relative' } }, btn);
  let pop;
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (pop) { pop.remove(); pop = null; return; }
    pop = h('div', { class: 'popover', style: { minWidth: '240px' } },
      h('div', { class: 'pop-head' }, `${u.username} · ${u.role_label}`),
      h('div', { class: 'pop-item', onclick: () => app.navigate('/settings') }, icon('gear'), 'Paramètres et permissions'),
      h('div', { class: 'pop-item', onclick: logout }, icon('logout'), 'Se déconnecter'));
    wrap.append(pop);
  });
  document.addEventListener('click', () => { if (pop) { pop.remove(); pop = null; } });
  return wrap;
}
async function logout() { await api.post('/auth/logout').catch(() => {}); app.user = null; showLogin(); }

// ------------------------------------------------------------------ routage
let currentPage = null;
export function setCrumbs(...parts) {
  const el = $('#crumbs'); if (!el) return;
  clear(el);
  parts.forEach((p, i) => { if (i) el.append(icon('chevron')); el.append(i === parts.length - 1 ? h('b', {}, p) : h('span', {}, p)); });
  el.querySelectorAll('svg').forEach((s) => { s.style.width = '13px'; s.style.height = '13px'; s.style.opacity = '.5'; });
  document.title = `${parts[parts.length - 1]} · ShopNOVA AI Security Lab`;
}
async function route() {
  if (!app.user) return;
  hideTip();
  document.querySelectorAll('.drawer-wrap, .overlay').forEach((el) => el.remove()); // aucune fenêtre ne survit à un changement de page
  const raw = location.hash.replace(/^#\/?/, '') || 'overview';
  const [path, query] = raw.split('?');
  const params = new URLSearchParams(query || '');
  const [name, arg] = path.split('/');
  const loader = PAGES[name] || PAGES.overview;
  document.querySelectorAll('.navtab[data-path]').forEach((a) => a.classList.toggle('active', a.dataset.path === path || (name === 'team' && a.dataset.path === `team/${arg}`)));
  moreBtn?.classList.toggle('active', ['registry', 'evidence', 'history', 'monitoring', 'reports', 'settings'].includes(name));
  const content = $('#content');
  const token = {}; currentPage = token;
  mount(content, h('div', { class: 'skeleton', style: { height: '42px', width: '40%', marginBottom: '18px' } }), h('div', { class: 'grid g-4' }, [1, 2, 3, 4].map(() => h('div', { class: 'skeleton', style: { height: '110px' } }))));
  try {
    const mod = await loader();
    if (currentPage !== token) return;
    const page = h('div', { class: 'page-enter' });
    mount(content, page);
    await mod.render(page, { app, arg, params });
  } catch (e) {
    if (currentPage !== token) return;
    mount(content, h('div', { class: 'error-box' }, e instanceof ApiError ? e.message : `Erreur d'affichage : ${e.message}`));
    if (!(e instanceof ApiError)) console.error(e);
  }
  content.focus({ preventScroll: true });
}
window.addEventListener('hashchange', route);
window.addEventListener('snv:unauthorized', () => { if (app.user) { app.user = null; toast('Session expirée : reconnectez-vous.', 'warn'); showLogin(); } });

// ------------------------------------------------------------------ connexion
function showLogin(errorMsg) {
  document.title = 'Connexion · ShopNOVA AI Security Lab';
  const user = h('input', { class: 'input', id: 'login-user', autocomplete: 'username', required: true, value: 'admin' });
  const pass = h('input', { class: 'input', id: 'login-pass', type: 'password', autocomplete: 'current-password', required: true });
  const err = h('div', { role: 'alert' }, errorMsg ? h('div', { class: 'error-box' }, errorMsg) : null);
  const submit = h('button', { class: 'btn primary', type: 'submit', style: { width: '100%', padding: '10px' } }, 'Se connecter');
  const form = h('form', { class: 'login-card card', onsubmit: async (e) => {
    e.preventDefault(); submit.classList.add('busy'); clear(err);
    try { const r = await api.post('/auth/login', { username: user.value, password: pass.value }); app.user = r.user; await boot(); }
    catch (ex) { mount(err, h('div', { class: 'error-box' }, ex.message)); }
    finally { submit.classList.remove('busy'); }
  } },
  h('h2', {}, 'Connexion'),
  h('div', { class: 'field', style: { marginTop: '18px' } }, h('label', { for: 'login-user' }, 'Identifiant'), user),
  h('div', { class: 'field', style: { marginTop: '12px' } }, h('label', { for: 'login-pass' }, 'Mot de passe'), pass),
  h('div', { style: { marginTop: '16px' } }, submit), err,
  h('div', { class: 'note', style: { marginTop: '18px' } }, 'Choisissez un rôle.',
    h('div', { class: 'demo-accounts' }, ['admin', 'agent', 'llm', 'rag', 'blue', 'auditor'].map((n) => h('button', { type: 'button', class: 'btn sm', onclick: () => { user.value = n; pass.focus(); } }, n)))));
  const art = h('div', { class: 'login-art' });
  mount(document.getElementById('app'), h('div', { class: 'login-wrap' }, art, h('div', { class: 'login-form' }, form)));
  applyTheme(false);
  // scène d'accueil : les trois composants IA et la couche défensive
  if (quality() !== 'off') {
    const box = h('div', { class: 'scene' }); art.append(box);
    const sc = new Scene3D(box, { height: 320, dist: 10, pitch: 0.32, autoRotate: 0.1, labels: false, grid: false, float: 0.12, scale: 0.85,
      nodes: [{ id: 'core', pos: [0, 0, 0], r: 0.55, color: 'var(--primary)' }, { id: 'a', pos: [-2, 0.2, 1.2], r: 0.36, color: 'var(--team-agt)' },
        { id: 'l', pos: [2, 0.1, 1.1], r: 0.36, color: 'var(--team-llm)' }, { id: 'r', pos: [0, 0.3, -2.2], r: 0.36, color: 'var(--team-rag)' }],
      edges: [['a', 'core'], ['l', 'core'], ['r', 'core']].map(([a, b]) => ({ a, b, flow: true, color: 'var(--secondary)', particles: 2 })),
      rings: [{ radius: 3.1, y: -0.2, color: 'var(--team-blue)', dashed: true, spin: 0.1 }] });
    if (sc.failed) box.remove();
  }
  art.append(h('div', { class: 'la-top' }, h('div', { class: 'brand' }, brandMark(),
    h('div', {}, h('div', { class: 'brand-name' }, 'SHOPNOVA'), h('div', { class: 'brand-sub' }, 'AI Security Lab'))),
  h('div', { style: { marginTop: '34px' } }, nova(96, 'nova-float')),
  h('h1', {}, 'Salut, je suis Nova. Essayez de me pirater.')));
  setTimeout(() => pass.focus(), 50);
}

async function boot() {
  app.meta = await api.get('/meta');
  buildShell();
  if (!location.hash) location.hash = '/overview'; else route();
}

(async function start() {
  try { const r = await api.get('/auth/me'); app.user = r.user; await boot(); }
  catch (e) { showLogin(e.status && e.status !== 401 ? e.message : null); }
})();
