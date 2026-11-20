// Client HTTP de la plateforme : cookie de session HttpOnly + en-tête anti-CSRF sur toute écriture.
export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function request(method, url, body) {
  const opts = { method, credentials: 'same-origin', headers: {} };
  if (method !== 'GET') opts.headers['X-Requested-With'] = 'shopnova';
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(url, opts); } catch { throw new ApiError(0, 'Serveur injoignable. Le lab est-il démarré ?'); }
  const type = res.headers.get('content-type') || '';
  const data = type.includes('json') ? await res.json().catch(() => ({})) : await res.text();
  if (!res.ok) {
    const msg = (data && data.detail) ? (typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)) : `Erreur ${res.status}`;
    if (res.status === 401 && !url.endsWith('/auth/login')) window.dispatchEvent(new CustomEvent('snv:unauthorized'));
    throw new ApiError(res.status, msg);
  }
  return data;
}

const S = '/api/secops';
export const api = {
  get: (p) => request('GET', S + p),
  post: (p, b = {}) => request('POST', S + p, b),
  patch: (p, b = {}) => request('PATCH', S + p, b),
  // API historiques du lab (CTF) : cibles du laboratoire, non authentifiées par conception
  ctf: {
    state: () => request('GET', '/api/ctf/state'),
    hint: (id) => request('POST', '/api/ctf/hint', { id }),
    attempt: (id, message, history = []) => request('POST', '/api/ctf/attempt', { id, message, history }),
    submit: (id, flag) => request('POST', '/api/ctf/submit', { id, flag }),
    reset: () => request('POST', '/api/ctf/reset', {}),
    mode: (secure) => request('POST', '/api/mode', { secure }),
    review: (product, author, text) => request('POST', '/api/review', { product, author, text }),
    notice: (text) => request('POST', '/api/notice', { text }),
  },
};

export function qs(params) {
  const s = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== '' && v !== null && v !== undefined));
  const out = s.toString();
  return out ? `?${out}` : '';
}
