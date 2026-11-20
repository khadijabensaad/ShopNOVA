// Graphiques SVG sans dépendance. Les couleurs sont des variables CSS (style="fill: var(--…)") :
// les graphiques suivent le thème clair/sombre sans être redessinés.
import { showTip, hideTip, h } from './ui.js';

const NS = 'http://www.w3.org/2000/svg';
function s(tag, attrs = {}, ...kids) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined) continue;
    if (k === 'style') el.setAttribute('style', v);
    else el.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k) el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return el;
}
function tipOn(el, title, text) {
  el.addEventListener('mousemove', (e) => showTip(e.clientX, e.clientY, title, text));
  el.addEventListener('mouseleave', hideTip);
  el.setAttribute('tabindex', '0');
  el.addEventListener('focus', () => { const r = el.getBoundingClientRect(); showTip(r.right, r.top, title, text); });
  el.addEventListener('blur', hideTip);
  return el;
}
function niceMax(v) { if (v <= 4) return 4; const p = 10 ** Math.floor(Math.log10(v)); const m = Math.ceil(v / p) * p; return Math.ceil(m / 4) * 4; }

export function bars({ categories, series, height = 220, stacked = false, unit = '', max, width = 380 }) {
  const W = width, H = height, padL = 34, padB = 26, padT = 10, padR = 8;
  const totals = categories.map((_, i) => stacked ? series.reduce((a, sr) => a + (sr.values[i] || 0), 0) : Math.max(...series.map((sr) => sr.values[i] || 0)));
  const top = max ?? niceMax(Math.max(1, ...totals));
  const svg = s('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Graphique en barres' });
  const iw = W - padL - padR, ih = H - padT - padB;
  for (let t = 0; t <= 4; t++) {
    const y = padT + ih - (ih * t) / 4;
    svg.append(s('line', { x1: padL, x2: W - padR, y1: y, y2: y, class: 'gridline' }), s('text', { x: padL - 6, y: y + 4, 'text-anchor': 'end' }, Math.round((top * t) / 4) + unit));
  }
  const gw = iw / categories.length, bw = stacked ? Math.min(46, gw * 0.5) : Math.min(26, (gw * 0.7) / series.length);
  categories.forEach((cat, i) => {
    const gx = padL + gw * i + gw / 2;
    let acc = 0;
    series.forEach((sr, j) => {
      const v = sr.values[i] || 0, bh = (ih * v) / top;
      const x = stacked ? gx - bw / 2 : gx - (bw * series.length) / 2 + j * bw + 1;
      const y = padT + ih - bh - (stacked ? (ih * acc) / top : 0);
      if (v > 0) svg.append(tipOn(s('rect', { x, y, width: stacked ? bw : bw - 2, height: Math.max(0, bh), rx: 3, style: `fill:${sr.color}` }), `${cat} · ${sr.name}`, `${v}${unit}`));
      acc += v;
    });
    svg.append(s('text', { x: gx, y: H - 8, 'text-anchor': 'middle' }, cat));
  });
  svg.append(s('line', { x1: padL, x2: W - padR, y1: padT + ih, y2: padT + ih, class: 'axis' }));
  return svg;
}

export function donut({ items, size = 168, thickness = 22, center, sub }) {
  const total = items.reduce((a, i) => a + i.value, 0);
  const r = size / 2 - 2, ir = r - thickness, c = size / 2;
  const svg = s('svg', { class: 'chart', viewBox: `0 0 ${size} ${size}`, width: size, height: size, role: 'img', 'aria-label': 'Graphique en anneau' });
  if (!total) {
    svg.append(s('circle', { cx: c, cy: c, r: (r + ir) / 2, style: 'fill:none;stroke:var(--border);', 'stroke-width': thickness }));
  } else {
    let a0 = -Math.PI / 2;
    for (const it of items) {
      if (!it.value) continue;
      const a1 = a0 + (2 * Math.PI * it.value) / total - (items.filter((i) => i.value).length > 1 ? 0.025 : 0);
      const large = a1 - a0 > Math.PI ? 1 : 0;
      const p = (rad, ang) => `${c + rad * Math.cos(ang)},${c + rad * Math.sin(ang)}`;
      const d = it.value === total
        ? `M ${c} ${c - r} A ${r} ${r} 0 1 1 ${c - 0.01} ${c - r} L ${c - 0.01} ${c - ir} A ${ir} ${ir} 0 1 0 ${c} ${c - ir} Z`
        : `M ${p(r, a0)} A ${r} ${r} 0 ${large} 1 ${p(r, a1)} L ${p(ir, a1)} A ${ir} ${ir} 0 ${large} 0 ${p(ir, a0)} Z`;
      svg.append(tipOn(s('path', { d, style: `fill:${it.color}` }), it.label, `${it.value} (${Math.round((100 * it.value) / total)} %)`));
      a0 = a1 + (items.filter((i) => i.value).length > 1 ? 0.025 : 0);
    }
  }
  svg.append(s('text', { x: c, y: c + 2, 'text-anchor': 'middle', style: 'font: 600 24px var(--font-display); fill: var(--text)' }, center ?? total));
  if (sub) svg.append(s('text', { x: c, y: c + 20, 'text-anchor': 'middle' }, sub));
  return svg;
}

export function legend(items) {
  return h('div', { class: 'legend' }, items.map((i) => h('span', {}, h('i', { style: { background: i.color } }), `${i.label}${i.value !== undefined ? ` · ${i.value}` : ''}`)));
}

export function hstack({ rows, height = 22 }) {
  const wrap = h('div', { style: { display: 'flex', flexDirection: 'column', gap: '10px' } });
  const max = Math.max(1, ...rows.map((r) => r.parts.reduce((a, p) => a + p.value, 0)));
  for (const r of rows) {
    const tot = r.parts.reduce((a, p) => a + p.value, 0);
    const bar = h('div', { style: { display: 'flex', height: `${height}px`, borderRadius: '6px', overflow: 'hidden', background: 'var(--bg-2)', width: `${Math.max(4, (100 * tot) / max)}%` } });
    for (const p of r.parts) {
      if (!p.value) continue;
      const seg = h('div', { style: { width: `${(100 * p.value) / tot}%`, background: p.color } });
      seg.addEventListener('mousemove', (e) => showTip(e.clientX, e.clientY, `${r.label} · ${p.label}`, String(p.value)));
      seg.addEventListener('mouseleave', hideTip);
      bar.append(seg);
    }
    wrap.append(h('div', { style: { display: 'grid', gridTemplateColumns: '110px 1fr 40px', gap: '10px', alignItems: 'center', fontSize: '13px' } },
      h('span', {}, r.label), tot ? bar : h('span', { class: 'faint', style: { fontSize: '12px' } }, 'aucune donnée'), h('span', { class: 'mono', style: { textAlign: 'right' } }, tot)));
  }
  return wrap;
}

export function timeline({ points, height = 200, width = 460 }) {
  // points : [{label, a, b}] — a = réussies, b = bloquées (aires empilées)
  const W = width, H = height, padL = 30, padB = 24, padT = 10, padR = 10;
  const iw = W - padL - padR, ih = H - padT - padB;
  const top = niceMax(Math.max(1, ...points.map((p) => p.a + p.b)));
  const svg = s('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': "Chronologie de l'activité" });
  for (let t = 0; t <= 4; t++) { const y = padT + ih - (ih * t) / 4; svg.append(s('line', { x1: padL, x2: W - padR, y1: y, y2: y, class: 'gridline' }), s('text', { x: padL - 6, y: y + 4, 'text-anchor': 'end' }, Math.round((top * t) / 4))); }
  const n = points.length;
  const X = (i) => padL + (n === 1 ? iw / 2 : (iw * i) / (n - 1));
  const Y = (v) => padT + ih - (ih * v) / top;
  if (n === 1) {
    const p = points[0], bw = 40;
    svg.append(tipOn(s('rect', { x: X(0) - bw / 2, y: Y(p.a + p.b), width: bw, height: Math.max(0, Y(p.b) - Y(p.a + p.b)), rx: 3, style: 'fill:var(--critical);opacity:.85' }), p.label, `${p.a} réussies`));
    svg.append(tipOn(s('rect', { x: X(0) - bw / 2, y: Y(p.b), width: bw, height: padT + ih - Y(p.b), rx: 3, style: 'fill:var(--success);opacity:.85' }), p.label, `${p.b} bloquées`));
  } else {
    const line = (f) => points.map((p, i) => `${i ? 'L' : 'M'} ${X(i)} ${Y(f(p))}`).join(' ');
    const area = (f, g) => `${line(f)} ${points.map((p, i) => `L ${X(n - 1 - i)} ${Y(g(points[n - 1 - i]))}`).join(' ')} Z`;
    svg.append(s('path', { d: area((p) => p.b, () => 0), style: 'fill:var(--success);opacity:.18' }));
    svg.append(s('path', { d: area((p) => p.a + p.b, (p) => p.b), style: 'fill:var(--critical);opacity:.18' }));
    svg.append(s('path', { d: line((p) => p.b), style: 'fill:none;stroke:var(--success);stroke-width:2' }));
    svg.append(s('path', { d: line((p) => p.a + p.b), style: 'fill:none;stroke:var(--critical);stroke-width:2' }));
    points.forEach((p, i) => svg.append(tipOn(s('circle', { cx: X(i), cy: Y(p.a + p.b), r: 3.5, style: 'fill:var(--card);stroke:var(--critical);stroke-width:2' }), p.label, `${p.a} réussies · ${p.b} bloquées`)));
  }
  const step = Math.max(1, Math.ceil(n / 6));
  points.forEach((p, i) => { if (i % step === 0 || i === n - 1) svg.append(s('text', { x: X(i), y: H - 6, 'text-anchor': 'middle' }, p.label)); });
  return svg;
}

export function ring(value, color = 'var(--primary)', size = 40) {
  const r = size / 2 - 4, c = size / 2, L = 2 * Math.PI * r;
  const v = value === null || value === undefined ? 0 : Math.max(0, Math.min(100, value));
  return s('svg', { width: size, height: size, viewBox: `0 0 ${size} ${size}`, 'aria-hidden': 'true' },
    s('circle', { cx: c, cy: c, r, style: 'fill:none;stroke:var(--bg-2)', 'stroke-width': 4 }),
    s('circle', { cx: c, cy: c, r, style: `fill:none;stroke:${color};transition:stroke-dashoffset .8s`, 'stroke-width': 4, 'stroke-linecap': 'round',
      'stroke-dasharray': L, 'stroke-dashoffset': L * (1 - v / 100), transform: `rotate(-90 ${c} ${c})` }));
}

export function sparkline(values, color = 'var(--primary)', w = 72, hgt = 26) {
  if (!values || values.length < 2) return null;
  const max = Math.max(1, ...values), min = Math.min(0, ...values);
  const X = (i) => (w * i) / (values.length - 1), Y = (v) => hgt - 2 - ((hgt - 4) * (v - min)) / (max - min || 1);
  return s('svg', { width: w, height: hgt, viewBox: `0 0 ${w} ${hgt}`, 'aria-hidden': 'true' },
    s('path', { d: values.map((v, i) => `${i ? 'L' : 'M'} ${X(i)} ${Y(v)}`).join(' '), style: `fill:none;stroke:${color};stroke-width:1.8` }));
}
