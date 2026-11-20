// Moteur 3D léger (canvas 2D + projection perspective), sans dépendance : fonctionne hors-ligne dans le lab.
// - nœuds (sphères, cubes, disques), liens animés avec particules (flux de données), anneaux (couche défensive)
// - rotation à la souris / au doigt, survol (infobulle), clic (navigation), flottement subtil
// - suit le thème (couleurs lues dans les variables CSS), respecte prefers-reduced-motion, se met en pause hors écran
// - repli automatique si le canvas n'est pas disponible ou si la 3D est désactivée dans les paramètres.
import { cssVar, prefersReducedMotion, h } from './ui.js';

function hexToRgb(hex) {
  const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})/i.exec(hex || '');
  return m ? [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16)] : [140, 140, 160];
}
const rgba = (rgb, a) => `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${a})`;
const mix = (rgb, t, to = [255, 255, 255]) => rgb.map((v, i) => Math.round(v + (to[i] - v) * t));

export function quality() {
  try { return localStorage.getItem('snv-3d') || 'high'; } catch { return 'high'; }
}

export class Scene3D {
  constructor(container, opts) {
    this.c = container; this.o = Object.assign({ height: 360, dist: 9, pitch: 0.42, yaw: 0.6, autoRotate: 0.08, floorY: -1.6,
      float: 0.08, grid: true, labels: true, rings: [], edges: [], nodes: [], scale: 1 }, opts);
    this.yaw = this.o.yaw; this.pitch = this.o.pitch; this.t = 0; this.hover = null; this.colors = new Map();
    this.reduced = prefersReducedMotion() || quality() === 'low';
    this.canvas = h('canvas', { role: 'img', 'aria-label': opts.label || 'Visualisation 3D', tabindex: '0' });
    this.c.append(this.canvas);
    this.ctx = this.canvas.getContext && this.canvas.getContext('2d');
    if (!this.ctx) { this.failed = true; return; }
    this.particles = this.o.edges.map((e) => e.flow ? Array.from({ length: e.particles || 3 }, (_, i) => i / (e.particles || 3)) : []);
    this.nodeIndex = new Map(this.o.nodes.map((n) => [n.id, n]));
    this.refreshColors();
    this.bind(); this.resize();
    this.onTheme = () => { this.refreshColors(); this.draw(); };
    window.addEventListener('snv:theme', this.onTheme);
    this.ro = new ResizeObserver(() => this.resize()); this.ro.observe(this.c);
    this.io = new IntersectionObserver(([e]) => { this.visible = e.isIntersecting; if (this.visible) this.loop(); }, { threshold: 0.05 });
    this.io.observe(this.c);
    this.last = performance.now();
    this.draw();
  }
  col(v) {
    if (!this.colors.has(v)) {
      const val = v && v.startsWith('var(') ? cssVar(v.slice(4, -1)) : v;
      this.colors.set(v, val || '#888');
    }
    return this.colors.get(v);
  }
  refreshColors() {
    this.colors.clear();
    this.text = this.col('var(--text)'); this.text2 = this.col('var(--text-2)'); this.card = this.col('var(--card)');
    this.border = this.col('var(--border)'); this.grid = this.col('var(--grid-line)');
    this.dark = document.documentElement.getAttribute('data-theme') !== 'light';
  }
  resize() {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const w = this.c.clientWidth || 600, hgt = this.o.height;
    this.w = w; this.h = hgt; this.canvas.width = w * dpr; this.canvas.height = hgt * dpr;
    this.canvas.style.height = `${hgt}px`; this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.draw();
  }
  bind() {
    let drag = null;
    const pos = (e) => { const r = this.canvas.getBoundingClientRect(); const p = e.touches ? e.touches[0] : e; return [p.clientX - r.left, p.clientY - r.top, p.clientX, p.clientY]; };
    this.canvas.addEventListener('pointerdown', (e) => { drag = { x: e.clientX, y: e.clientY, yaw: this.yaw, pitch: this.pitch, moved: false }; this.canvas.setPointerCapture(e.pointerId); this.canvas.classList.add('drag'); });
    this.canvas.addEventListener('pointermove', (e) => {
      const [x, y, cx, cy] = pos(e);
      if (drag) {
        const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
        if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
        this.yaw = drag.yaw + dx * 0.008; this.pitch = Math.max(0.05, Math.min(1.1, drag.pitch + dy * 0.005)); this.interacted = performance.now();
        this.draw(); return;
      }
      const hit = this.hit(x, y);
      if (hit !== this.hover) { this.hover = hit; this.canvas.style.cursor = hit && (hit.href || this.o.onClick) ? 'pointer' : 'grab'; this.draw(); }
      if (this.o.onHover) this.o.onHover(hit, cx, cy);
    });
    const up = (e) => {
      if (drag && !drag.moved) { const [x, y] = pos(e); const hit = this.hit(x, y); if (hit && this.o.onClick) this.o.onClick(hit); }
      drag = null; this.canvas.classList.remove('drag');
    };
    this.canvas.addEventListener('pointerup', up);
    this.canvas.addEventListener('pointerleave', () => { this.hover = null; if (this.o.onHover) this.o.onHover(null); this.draw(); });
    this.canvas.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowLeft') this.yaw -= 0.15; else if (e.key === 'ArrowRight') this.yaw += 0.15;
      else if (e.key === 'ArrowUp') this.pitch = Math.max(0.05, this.pitch - 0.08); else if (e.key === 'ArrowDown') this.pitch = Math.min(1.1, this.pitch + 0.08);
      else return;
      e.preventDefault(); this.interacted = performance.now(); this.draw();
    });
  }
  project([x, y, z]) {
    const cy = Math.cos(this.yaw), sy = Math.sin(this.yaw), cp = Math.cos(this.pitch), sp = Math.sin(this.pitch);
    const x1 = x * cy - z * sy, z1 = x * sy + z * cy;
    const y2 = y * cp - z1 * sp, z2 = y * sp + z1 * cp;
    const f = (Math.min(this.w, this.h * 1.6) * 0.62 * this.o.scale) / 4.2;
    const k = this.o.dist / (this.o.dist + z2);
    return { x: this.w / 2 + x1 * f * k, y: this.h / 2 - y2 * f * k + (this.o.offsetY || 0), k, z: z2, f };
  }
  nodePos(n) {
    const amp = this.reduced ? 0 : (n.float ?? this.o.float);
    return [n.pos[0], n.pos[1] + Math.sin(this.t * 1.1 + (n.phase ?? n.pos[0] * 1.7 + n.pos[2])) * amp, n.pos[2]];
  }
  hit(x, y) {
    let best = null;
    for (const n of this.o.nodes) {
      if (n.hidden || !n._p) continue;
      const d = Math.hypot(x - n._p.x, y - n._p.y);
      if (d <= Math.max(14, n._r + 4) && (!best || n._p.z < best._p.z)) best = n;
    }
    return best;
  }
  loop() {
    if (this.raf || this.failed) return;
    const step = (now) => {
      this.raf = null;
      if (!this.canvas.isConnected) { this.destroy(); return; }
      if (!this.visible) return;
      const dt = Math.min(0.05, (now - this.last) / 1000); this.last = now;
      if (!this.reduced) {
        this.t += dt;
        const idle = !this.interacted || now - this.interacted > 2500;
        if (idle && this.o.autoRotate) this.yaw += dt * this.o.autoRotate;
        this.particles.forEach((ps, i) => { const sp = this.o.edges[i].speed || 0.35; for (let j = 0; j < ps.length; j++) ps[j] = (ps[j] + dt * sp) % 1; });
      }
      this.draw();
      if (!this.reduced) this.raf = requestAnimationFrame(step);
    };
    this.raf = requestAnimationFrame(step);
  }
  destroy() {
    if (this.raf) cancelAnimationFrame(this.raf);
    this.ro?.disconnect(); this.io?.disconnect(); window.removeEventListener('snv:theme', this.onTheme);
  }
  update(patch) { // met à jour des nœuds/liens (statuts) sans recréer la scène
    if (patch.nodes) for (const p of patch.nodes) Object.assign(this.nodeIndex.get(p.id) || {}, p);
    if (patch.edges) patch.edges.forEach((p, i) => Object.assign(this.o.edges[i], p));
    this.draw();
  }
  draw() {
    if (this.failed || !this.w) return;
    const ctx = this.ctx; ctx.clearRect(0, 0, this.w, this.h);
    // sol en perspective
    if (this.o.grid) {
      ctx.lineWidth = 1; ctx.strokeStyle = this.grid;
      const fy = this.o.floorY, R = 5;
      for (let i = -R; i <= R; i++) {
        const a = this.project([i, fy, -R]), b = this.project([i, fy, R]); ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        const c = this.project([-R, fy, i]), d = this.project([R, fy, i]); ctx.beginPath(); ctx.moveTo(c.x, c.y); ctx.lineTo(d.x, d.y); ctx.stroke();
      }
    }
    for (const n of this.o.nodes) { const p = this.project(this.nodePos(n)); n._p = p; n._r = (n.r || 0.3) * p.f * p.k; }
    const items = [];
    // anneaux (couche défensive) découpés en segments pour un tri en profondeur correct
    for (const ring of this.o.rings) {
      const N = 96, pts = [];
      for (let i = 0; i <= N; i++) { const a = (i / N) * Math.PI * 2 + (this.reduced ? 0 : this.t * (ring.spin || 0)); pts.push(this.project([Math.cos(a) * ring.radius, ring.y, Math.sin(a) * ring.radius])); }
      for (let i = 0; i < N; i++) items.push({ z: (pts[i].z + pts[i + 1].z) / 2, draw: () => {
        ctx.strokeStyle = rgba(hexToRgb(this.col(ring.color)), ring.alpha ?? 0.55); ctx.lineWidth = (ring.width || 2) * pts[i].k;
        if (ring.dashed && i % 3 === 2) return;
        ctx.beginPath(); ctx.moveTo(pts[i].x, pts[i].y); ctx.lineTo(pts[i + 1].x, pts[i + 1].y); ctx.stroke();
      } });
      if (ring.label && pts.length) {
        const lp = pts.reduce((a, b) => (b.y < a.y ? b : a)); // point le plus haut à l'écran : jamais sous la légende
        items.push({ z: lp.z - 0.01, draw: () => this.pill(lp.x, lp.y - 12, ring.label, this.col(ring.color), true) });
      }
    }
    // liens
    this.o.edges.forEach((e, idx) => {
      const A = this.nodeIndex.get(e.a), B = this.nodeIndex.get(e.b); if (!A || !B || A.hidden || B.hidden) return;
      const pa = this.nodePos(A), pb = this.nodePos(B);
      const mid = [(pa[0] + pb[0]) / 2, (pa[1] + pb[1]) / 2 + (e.arc ?? 0.35), (pa[2] + pb[2]) / 2];
      const curve = (t) => [0, 1, 2].map((k) => (1 - t) * (1 - t) * pa[k] + 2 * (1 - t) * t * mid[k] + t * t * pb[k]);
      const N = 24, pts = Array.from({ length: N + 1 }, (_, i) => this.project(curve(i / N)));
      const rgb = hexToRgb(this.col(e.color || 'var(--border-strong)'));
      const hl = this.hover && (this.hover.id === e.a || this.hover.id === e.b);
      items.push({ z: (pts[0].z + pts[N].z) / 2 + 0.2, draw: () => {
        ctx.save(); ctx.lineWidth = (e.width || 1.6) * (hl ? 1.6 : 1); ctx.strokeStyle = rgba(rgb, hl ? 0.95 : (e.alpha ?? 0.55));
        if (e.dashed) ctx.setLineDash([5, 5]);
        ctx.beginPath(); pts.forEach((p, i) => (i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y))); ctx.stroke(); ctx.restore();
        if (e.arrow) { const a = pts[N - 3], b = pts[N - 1]; const ang = Math.atan2(b.y - a.y, b.x - a.x); ctx.fillStyle = rgba(rgb, 0.9); ctx.beginPath();
          ctx.moveTo(b.x, b.y); ctx.lineTo(b.x - 8 * Math.cos(ang - 0.4), b.y - 8 * Math.sin(ang - 0.4)); ctx.lineTo(b.x - 8 * Math.cos(ang + 0.4), b.y - 8 * Math.sin(ang + 0.4)); ctx.fill(); }
        for (const t of this.particles[idx] || []) { const p = this.project(curve(t)); ctx.fillStyle = rgba(rgb, 0.95); ctx.beginPath(); ctx.arc(p.x, p.y, 2.4 * p.k, 0, 7); ctx.fill();
          ctx.fillStyle = rgba(rgb, 0.18); ctx.beginPath(); ctx.arc(p.x, p.y, 6 * p.k, 0, 7); ctx.fill(); }
      } });
    });
    // nœuds
    for (const n of this.o.nodes) {
      if (n.hidden) continue;
      items.push({ z: n._p.z, draw: () => this.drawNode(n) });
    }
    items.sort((a, b) => b.z - a.z).forEach((i) => i.draw());
  }
  drawNode(n) {
    const ctx = this.ctx, p = n._p, r = n._r, rgb = hexToRgb(this.col(n.color || 'var(--primary)'));
    const hl = this.hover === n || n.highlight;
    // ombre portée sur le sol
    const fp = this.project([n.pos[0], this.o.floorY, n.pos[2]]);
    if (this.o.grid) { ctx.fillStyle = `rgba(0,0,0,${this.dark ? 0.32 : 0.08})`; ctx.beginPath(); ctx.ellipse(fp.x, fp.y, r * 1.05, r * 0.32, 0, 0, 7); ctx.fill(); }
    if (n.halo || hl) { ctx.fillStyle = rgba(rgb, hl ? 0.22 : 0.12); ctx.beginPath(); ctx.arc(p.x, p.y, r * (hl ? 1.9 : 1.6), 0, 7); ctx.fill(); }
    const shape = n.shape || 'sphere';
    if (shape === 'sphere') {
      const g = ctx.createRadialGradient(p.x - r * 0.35, p.y - r * 0.4, r * 0.1, p.x, p.y, r);
      g.addColorStop(0, rgba(mix(rgb, 0.55), 1)); g.addColorStop(0.55, rgba(rgb, 1)); g.addColorStop(1, rgba(mix(rgb, 0.45, [0, 0, 0]), 1));
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, 7); ctx.fill();
    } else if (shape === 'cube' || shape === 'card') {
      const s = n.r || 0.3, [x, y, z] = this.nodePos(n), sx = shape === 'card' ? s * 1.3 : s, sy = shape === 'card' ? s * 0.85 : s, sz = shape === 'card' ? s * 0.18 : s;
      const v = [[-sx, -sy, -sz], [sx, -sy, -sz], [sx, sy, -sz], [-sx, sy, -sz], [-sx, -sy, sz], [sx, -sy, sz], [sx, sy, sz], [-sx, sy, sz]].map(([a, b, c]) => this.project([x + a, y + b, z + c]));
      const faces = [[0, 1, 2, 3, 0.75], [4, 5, 6, 7, 0.75], [0, 1, 5, 4, 0.55], [3, 2, 6, 7, 1], [0, 3, 7, 4, 0.65], [1, 2, 6, 5, 0.85]];
      faces.map((f) => ({ f, z: (v[f[0]].z + v[f[1]].z + v[f[2]].z + v[f[3]].z) / 4 })).sort((a, b) => b.z - a.z).forEach(({ f }) => {
        ctx.fillStyle = rgba(mix(rgb, (1 - f[4]) * 0.6, [0, 0, 0]), 0.96); ctx.strokeStyle = rgba(mix(rgb, 0.4), 0.9); ctx.lineWidth = 1;
        ctx.beginPath(); for (let i = 0; i < 4; i++) { const q = v[f[i]]; i ? ctx.lineTo(q.x, q.y) : ctx.moveTo(q.x, q.y); } ctx.closePath(); ctx.fill(); ctx.stroke();
      });
    } else if (shape === 'disc') {
      ctx.fillStyle = rgba(rgb, 0.18); ctx.strokeStyle = rgba(rgb, 0.95); ctx.lineWidth = 2; ctx.setLineDash(n.dashed ? [4, 4] : []);
      ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, 7); ctx.fill(); ctx.stroke(); ctx.setLineDash([]);
    }
    if (n.badge) { ctx.fillStyle = this.col(n.badgeColor || 'var(--critical)'); ctx.beginPath(); ctx.arc(p.x + r * 0.75, p.y - r * 0.75, 5.5, 0, 7); ctx.fill(); }
    if (n.glyph) { ctx.fillStyle = '#fff'; ctx.font = `700 ${Math.max(9, r * 0.62)}px ui-monospace, monospace`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText(n.glyph, p.x, p.y + 1); }
    if (this.o.labels && n.label) this.pill(p.x, p.y + r + 14, n.label, hl ? this.col(n.color) : null, false, n.sub);
  }
  pill(x, y, text, accent, small, sub) {
    const ctx = this.ctx; ctx.font = `600 ${small ? 10.5 : 11.5}px Nunito, system-ui, sans-serif`;
    const w = ctx.measureText(text).width + 14, hgt = small ? 18 : 20;
    ctx.fillStyle = this.card; ctx.strokeStyle = accent || this.border; ctx.lineWidth = 1;
    const rr = 6, x0 = x - w / 2, y0 = y - hgt / 2;
    ctx.beginPath(); ctx.moveTo(x0 + rr, y0); ctx.arcTo(x0 + w, y0, x0 + w, y0 + hgt, rr); ctx.arcTo(x0 + w, y0 + hgt, x0, y0 + hgt, rr); ctx.arcTo(x0, y0 + hgt, x0, y0, rr); ctx.arcTo(x0, y0, x0 + w, y0, rr); ctx.closePath();
    ctx.globalAlpha = 0.92; ctx.fill(); ctx.globalAlpha = 1; ctx.stroke();
    ctx.fillStyle = small && accent ? accent : this.text; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText(text, x, y + 0.5);
    if (sub) { ctx.font = '500 10px Nunito, system-ui, sans-serif'; ctx.fillStyle = this.text2; ctx.fillText(sub, x, y + hgt / 2 + 9); }
  }
}

// Fabrique : retourne l'élément conteneur (.scene) et la scène, avec repli si 3D désactivée/indisponible.
export function sceneBox(opts, fallback) {
  const box = h('div', { class: 'scene', style: { height: `${opts.height || 360}px` } });
  if (quality() === 'off') { box.style.height = 'auto'; box.append(h('div', { class: 'scene-fallback' }, fallback())); return { box, scene: null }; }
  if (opts.title) box.append(h('div', { class: 'scene-label' }, opts.title));
  const scene = new Scene3D(box, opts);
  if (scene.failed) { box.style.height = 'auto'; box.append(h('div', { class: 'scene-fallback' }, fallback())); return { box, scene: null }; }
  if (opts.legend) box.append(h('div', { class: 'scene-hud' }, opts.legend.map(([c, l]) => h('span', {}, h('i', { style: { background: c } }), l))));
  return { box, scene };
}
