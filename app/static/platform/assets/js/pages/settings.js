// Settings : apparence (thème, mouvement, 3D), compte et permissions, santé du lab, administration.
import { api } from '../api.js';
import { h, icon, mount, card, seg, badge, toast, confirmDialog, dataTable } from '../ui.js';
import { setCrumbs } from '../main.js';

export async function render(root, { app }) {
  setCrumbs('Laboratoire', 'Settings');
  const reload = () => render(root, { app });
  const theme = localStorage.getItem('snv-theme') || 'system';
  const reduce = localStorage.getItem('snv-reduce-motion') === '1';
  const q3d = localStorage.getItem('snv-3d') || 'high';
  const health = await api.get('/health').catch(() => null);
  const users = app.can('admin') ? (await api.get('/users')).users : null;
  const row = (label, desc, control) => h('div', { class: 'li', style: { alignItems: 'center' } }, h('div', { class: 'li-main' }, h('div', { class: 'li-title' }, label), h('div', { class: 'li-sub' }, desc)), control);
  const ok = (v) => (v ? badge('Disponible', 'b-success', 'check') : badge('Indisponible', 'b-warning', 'alert'));
  mount(root,
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', { class: 'page-title' }, 'Paramètres'),
      h('p', { class: 'page-sub' }, 'Préférences d\'affichage (enregistrées dans ce navigateur), permissions de votre rôle et état du laboratoire.'))),
    app.meta.lab.default_password ? h('div', { class: 'error-box', style: { marginBottom: '16px' } }, h('b', {}, 'Mot de passe par défaut actif. '),
      'Définissez PLATFORM_PASSWORD dans .env (python setup_flags.py le génère) puis supprimez data/secops.db pour recréer les comptes.') : null,
    h('div', { class: 'grid g-2' },
      card('Apparence', null, h('div', { class: 'list' },
        row('Thème', 'Clair, sombre ou selon le système. Conservé entre les sessions, appliqué avant l\'affichage (aucun flash).',
          seg([['light', 'Clair'], ['dark', 'Sombre'], ['system', 'Système']], theme, (v) => { app.setTheme(v); })),
        row('Réduire les animations', 'Désactive transitions, rotation et particules (en plus de la préférence du système).',
          h('input', { type: 'checkbox', checked: reduce, 'aria-label': 'Réduire les animations', onchange: (e) => {
            localStorage.setItem('snv-reduce-motion', e.target.checked ? '1' : '0'); document.documentElement.classList.toggle('reduce-motion', e.target.checked); toast('Préférence enregistrée');
          } })),
        row('Visualisations 3D', 'Haute qualité (animée), légère (statique) ou désactivée (vue 2D de repli).',
          seg([['high', 'Haute'], ['low', 'Légère'], ['off', 'Désactivée']], q3d, (v) => { localStorage.setItem('snv-3d', v); toast('Préférence 3D enregistrée'); })))),
      card('Compte et permissions', app.user.role_label, h('div', { class: 'card-body' },
        h('dl', { class: 'kv' }, h('dt', {}, 'Utilisateur'), h('dd', { class: 'mono' }, app.user.username), h('dt', {}, 'Nom'), h('dd', {}, app.user.display_name),
          h('dt', {}, 'Rôle'), h('dd', {}, app.user.role_label), h('dt', {}, 'Équipe'), h('dd', {}, app.user.team || '—'),
          h('dt', {}, 'Permissions'), h('dd', { style: { display: 'flex', flexWrap: 'wrap', gap: '6px' } }, app.user.permissions.map((p) => badge(p, 'neutral')))),
        h('div', { class: 'note', style: { marginTop: '12px' } }, 'Les permissions sont vérifiées par le serveur à chaque requête ; masquer ou afficher un menu ne change aucun droit.')))),
    h('div', { class: 'grid g-2 mt' },
      card('État du laboratoire', 'vérifié à l\'instant', h('div', { class: 'list' }, health ? [
        row('Modèle de chat', `${app.meta.lab.model} via ${app.meta.lab.ollama}`, ok(health.llm)),
        row('Bibliothèque MCP', 'Serveur d\'outils shopnova-tools (stdio)', ok(health.mcp)),
        row('Base vectorielle', `ChromaDB · embeddings ${app.meta.lab.embed_model}`, ok(health.rag)),
        row('Données fictives', 'data/shop.db (clients et commandes Faker)', ok(health.shop_db)),
        row('Mode global du lab', 'Basculé par les défis CTF ; la plateforme passe le mode explicitement à chaque test.', health.secure_mode_global ? badge('Sécurisé', 'b-success') : badge('Vulnérable', 'b-danger'))]
        : h('div', { class: 'li' }, 'Indisponible.'))),
      card('Matrice des rôles', 'RBAC côté serveur', dataTable({ rows: Object.entries(app.meta.roles).map(([k, v]) => ({ k, ...v })), pageSize: 10, columns: [
        { key: 'label', label: 'Rôle' }, { key: 'team', label: 'Équipe', render: (r) => r.team || '—' },
        { key: 'permissions', label: 'Permissions', sortable: false, render: (r) => h('span', { class: 'mono faint', style: { fontSize: '11px' } }, r.permissions.join(' · ')) }] }))),
    users ? h('div', { class: 'grid g-2 mt' },
      card('Utilisateurs', `${users.length} comptes`, dataTable({ rows: users, pageSize: 10, columns: [{ key: 'username', label: 'Identifiant', render: (u) => h('span', { class: 'mono' }, u.username) },
        { key: 'display_name', label: 'Nom' }, { key: 'role_label', label: 'Rôle' }, { key: 'active', label: 'Actif', render: (u) => (u.active ? badge('oui', 'b-success') : badge('non')) }] })),
      card('Administration', 'action journalisée', h('div', { class: 'card-body' },
        h('p', { class: 'muted', style: { marginTop: 0 } }, 'Efface l\'activité de la plateforme (exécutions, preuves, findings, événements, incidents). Les comptes et le journal d\'audit sont conservés. Le CTF n\'est pas affecté.'),
        h('button', { class: 'btn danger', onclick: async () => {
          if (!(await confirmDialog('Effacer l\'activité ?', 'Cette action supprime définitivement toutes les exécutions, preuves et findings de la plateforme.', 'Effacer', 'danger'))) return;
          await api.post('/admin/reset-activity'); toast('Activité effacée'); reload();
        } }, icon('x'), 'Effacer l\'activité de la plateforme')))) : null);
}
