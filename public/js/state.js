export const state = {
  traces: [],
  selectedTraceId: null,
  baselineTraceId: null,
  expandedTraces: new Set(),
  redirectMutations: [],
  paramMutations: [],
  tokenMutations: [],
  customPresets: [],
  customBatchData: null,
  batchResults: new Map(),
  paramBatchResults: new Map(),
  tokenBatchResults: new Map(),
};

export const $ = (id) => document.getElementById(id);

export async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok && !data.error) {
    data.error = `HTTP ${res.status} ${res.statusText}`;
  }
  return data;
}

export async function withBusyButton(btn, busyText, fn) {
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = busyText;
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

export function statusBadgeClass(status) {
  if (!status) return 'badge-muted';
  if (status >= 200 && status < 300) return 'badge-ok';
  if (status >= 300 && status < 400) return 'badge-info';
  if (status >= 400 && status < 500) return 'badge-warn';
  return 'badge-danger';
}

export function severityBadgeClass(sev) {
  if (sev === 'HIGH') return 'badge-danger';
  if (sev === 'MEDIUM') return 'badge-warn';
  if (sev === 'LOW') return 'badge-info';
  return 'badge-muted';
}

export function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

export function toBase64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function randomToken(len = 32) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

export function showCopyFeedback(msg) {
  $('copyFeedback').textContent = msg;
  setTimeout(() => {
    if ($('copyFeedback').textContent === msg) $('copyFeedback').textContent = '';
  }, 2000);
}

export async function copyToClipboard(text, label) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      throw new Error('Clipboard API unavailable');
    }
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  showCopyFeedback(label);
}
