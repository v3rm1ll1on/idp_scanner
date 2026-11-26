import {
  state,
  $,
  api,
  escapeHtml,
  statusBadgeClass,
  severityBadgeClass,
  copyToClipboard,
} from './state.js';
import { refreshRedirectMutations, refreshCustomParamOptions } from './fuzzers.js';

export async function loadTraces() {
  const data = await api('/api/traces');
  state.traces = data.traces || [];
  if (!state.selectedTraceId && state.traces.length > 0) {
    state.selectedTraceId = state.traces[0].id;
  }
  renderTraceList();
  renderSelectedTrace();
  renderSequenceDiagram();
}

export async function refreshCookieJarBadge() {
  const data = await api('/api/cookies');
  $('cookieJarBadge').textContent = `Cookies: ${(data.cookies || []).length}`;
}

export async function copyTraceAsCurl(trace) {
  const parts = [`curl -i -X ${trace.request.method}`];
  for (const [k, v] of Object.entries(trace.request.headers || {})) {
    parts.push(`-H ${JSON.stringify(`${k}: ${v}`)}`);
  }
  if (trace.request.body) {
    parts.push(`--data-raw ${JSON.stringify(trace.request.body)}`);
  }
  parts.push(JSON.stringify(trace.request.url));
  await copyToClipboard(parts.join(' \\\n  '), 'Copied cURL');
}

function formatTraceTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString().slice(11, 23);
}

function renderTraceParamsHtml(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const entries = [...u.searchParams.entries()];
    if (entries.length === 0) return '';
    return `<div class="trace-params">${entries
      .slice(0, 6)
      .map(([k, v]) => {
        const valCls =
          k === 'error' || k === 'error_description'
            ? 'tp-v-err'
            : k === 'code' || k === 'access_token' || k === 'id_token'
              ? 'tp-v-cred'
              : 'tp-v';
        const shortVal = v.length > 26 ? `${v.slice(0, 23)}...` : v;
        return `<span class="tp-pair" title="${escapeHtml(`${k}=${v}`)}"><span class="tp-k">${escapeHtml(k)}</span><span class="tp-eq">=</span><span class="${valCls}">${escapeHtml(shortVal)}</span></span>`;
      })
      .join('')}${entries.length > 6 ? `<span class="muted">+${entries.length - 6}</span>` : ''}</div>`;
  } catch {
    return '';
  }
}

export function renderTraceList() {
  $('traceCount').textContent = String(state.traces.length);
  const container = $('traceList');
  if (state.traces.length === 0) {
    container.innerHTML = '<div class="muted" style="padding:12px;">No traces yet. Paste a URL/request or send a request.</div>';
    return;
  }

  container.innerHTML = state.traces
    .map((t) => {
      const active = t.id === state.selectedTraceId ? 'active' : '';
      const expanded = state.expandedTraces.has(t.id) ? 'expanded' : '';
      const findingsCount = (t.audit?.findings || []).filter((f) => f.severity === 'HIGH' || f.severity === 'MEDIUM').length;
      const urlObj = (() => {
        try { return new URL(t.request.url); } catch { return { pathname: t.request.url }; }
      })();
      const timeStr = formatTraceTime(t.timestamp).slice(0, 8);
      return `
        <div class="trace-item ${active} ${expanded}" data-id="${t.id}">
          <div class="trace-compact-row">
            <button class="trace-expand-btn" data-id="${t.id}" data-tip="Expand / collapse query params & actions">${expanded ? '▾' : '▸'}</button>
            <span class="badge badge-muted">${escapeHtml(t.request.method)}</span>
            <span class="badge ${statusBadgeClass(t.response.status)}">${t.response.status || 'ERR'}</span>
            <span class="trace-path" title="${escapeHtml(t.request.url)}">${escapeHtml(urlObj.pathname)}</span>
            <span class="trace-time" title="${escapeHtml(t.timestamp || '')}">${escapeHtml(timeStr)}${findingsCount ? ` · <span style="color:#fbbf24">${findingsCount}f</span>` : ''}</span>
          </div>
          <div class="trace-details">
            ${renderTraceParamsHtml(t.request.url)}
            <div class="trace-row">
              <span class="muted" style="font-size:10.5px;">${escapeHtml(t.flowKind || t.label)} · ${t.durationMs}ms</span>
              <span class="trace-actions">
                <button class="btn-mini trace-copy-curl" data-id="${t.id}" data-tip="Copy this request as cURL">cURL</button>
                <button class="btn-mini trace-to-rep" data-id="${t.id}" data-tip="Load into Repeater">-&gt; Rep</button>
              </span>
            </div>
          </div>
        </div>
      `;
    })
    .join('');

  container.querySelectorAll('.trace-expand-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      if (state.expandedTraces.has(id)) state.expandedTraces.delete(id);
      else state.expandedTraces.add(id);
      renderTraceList();
    });
  });

  container.querySelectorAll('.trace-copy-curl').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const trace = state.traces.find((t) => t.id === btn.dataset.id);
      if (trace) copyTraceAsCurl(trace);
    });
  });

  container.querySelectorAll('.trace-to-rep').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      state.selectedTraceId = btn.dataset.id;
      renderTraceList();
      renderSelectedTrace();
      renderSequenceDiagram();
      document.querySelector('[data-tab="repeater"]').click();
    });
  });

  container.querySelectorAll('.trace-item').forEach((el) => {
    el.addEventListener('click', () => {
      state.selectedTraceId = el.dataset.id;
      renderTraceList();
      renderSelectedTrace();
      renderSequenceDiagram();
    });
  });
}

function renderKvTable(el, obj) {
  const entries = Object.entries(obj || {});
  if (entries.length === 0) {
    el.innerHTML = '<div class="muted" style="padding:6px 8px;">(none)</div>';
    return;
  }
  el.innerHTML = `<table class="kv-table"><tbody>${entries
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(typeof v === 'string' ? v : JSON.stringify(v))}</td></tr>`)
    .join('')}</tbody></table>`;
}

function renderCookiesTable(el, cookies) {
  if (!cookies || cookies.length === 0) {
    el.innerHTML = '<div class="muted" style="padding:6px 8px;">(no Set-Cookie headers)</div>';
    return;
  }
  el.innerHTML = `<table class="kv-table"><tbody>${cookies
    .map((c) => {
      const flags = [
        c.httpOnly ? 'HttpOnly' : '!HttpOnly',
        c.secure ? 'Secure' : '!Secure',
        c.sameSite ? `SameSite=${c.sameSite}` : '!SameSite',
        c.domain ? `Domain=${c.domain}` : '',
        c.path ? `Path=${c.path}` : '',
      ]
        .filter(Boolean)
        .join(' · ');
      return `<tr><td>${escapeHtml(c.name)}</td><td><div>${escapeHtml(c.value)}</div><div class="muted">${escapeHtml(flags)}</div></td></tr>`;
    })
    .join('')}</tbody></table>`;
}

function renderDiffBanner(trace) {
  const banner = $('diffBanner');
  if (!state.baselineTraceId || !trace) {
    banner.style.display = 'none';
    return;
  }
  const base = state.traces.find((t) => t.id === state.baselineTraceId);
  if (!base) {
    banner.style.display = 'none';
    return;
  }
  if (base.id === trace.id) {
    banner.style.display = 'flex';
    banner.innerHTML = '<span><strong>Baseline active</strong> (select another trace to compare)</span>';
    return;
  }
  const statusDelta = `${base.response.status} -> ${trace.response.status}`;
  const lenBase = (base.response.body || '').length;
  const lenCur = (trace.response.body || '').length;
  const lenDelta = lenCur - lenBase;
  const locChanged = (base.response.location || '') !== (trace.response.location || '');
  banner.style.display = 'flex';
  banner.innerHTML = `
    <span><strong>Diff vs Baseline:</strong></span>
    <span>Status: <strong>${escapeHtml(statusDelta)}</strong></span>
    <span>Body Len: <strong>${lenBase} -> ${lenCur} (${lenDelta >= 0 ? '+' : ''}${lenDelta})</strong></span>
    <span>Location: <strong>${locChanged ? 'CHANGED' : 'SAME'}</strong></span>
  `;
}

function formatBody(body) {
  if (!body) return '(empty)';
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

export function renderSelectedTrace() {
  const trace = state.traces.find((t) => t.id === state.selectedTraceId);
  if (!trace) {
    $('diffBanner').style.display = 'none';
    $('reqSummary').textContent = 'No trace selected.';
    renderKvTable($('reqOAuthParams'), {});
    renderKvTable($('reqHeaders'), {});
    $('reqBody').textContent = '';
    $('resStatusBadge').innerHTML = '';
    $('resSummary').textContent = 'No trace selected.';
    renderKvTable($('resOAuthParams'), {});
    renderCookiesTable($('resCookies'), []);
    renderKvTable($('resHeaders'), {});
    $('resBody').textContent = '';
    renderAudit(null);
    return;
  }

  renderDiffBanner(trace);
  $('reqSummary').textContent = `${trace.request.method} ${trace.request.url}`;
  renderKvTable($('reqOAuthParams'), trace.request.oauthParams || {});
  renderKvTable($('reqHeaders'), trace.request.headers || {});
  $('reqBody').textContent = trace.request.body || '(empty)';

  $('resStatusBadge').innerHTML = `<span class="badge ${statusBadgeClass(trace.response.status)}">${trace.response.status} ${escapeHtml(trace.response.statusText || '')}</span>`;
  if (trace.response.location) {
    let resolvedLoc = trace.response.location;
    try {
      resolvedLoc = new URL(trace.response.location, trace.request.url).toString();
    } catch {
      // Keep raw location
    }
    const isHttp = /^https?:\/\//i.test(resolvedLoc);
    $('resSummary').innerHTML =
      `HTTP ${trace.response.status} -&gt; Location: ` +
      `<a href="#" class="loc-load-rep" data-url="${escapeHtml(resolvedLoc)}" style="color:#38bdf8;text-decoration:underline;" data-tip="Click to load this Location URL into Repeater">${escapeHtml(trace.response.location)}</a>` +
      (isHttp ? ` <a href="${escapeHtml(resolvedLoc)}" target="_blank" rel="noopener noreferrer" class="badge badge-info" style="margin-left:6px;text-decoration:none;" data-tip="Open Location URL in new browser tab">Open</a>` : '');
    $('resSummary').querySelector('.loc-load-rep')?.addEventListener('click', (e) => {
      e.preventDefault();
      $('repMethod').value = 'GET';
      $('repUrl').value = resolvedLoc;
      $('repHeaders').value = '{}';
      $('repBody').value = '';
      refreshCustomParamOptions();
      document.querySelector('[data-tab="repeater"]').click();
    });
  } else {
    $('resSummary').textContent = `HTTP ${trace.response.status} (${trace.durationMs}ms)`;
  }
  renderKvTable($('resOAuthParams'), trace.response.oauthParams || {});
  renderCookiesTable($('resCookies'), trace.response.cookies || []);
  renderKvTable($('resHeaders'), trace.response.headers || {});
  $('resBody').textContent = formatBody(trace.response.body);

  $('repMethod').value = trace.request.method || 'GET';
  $('repUrl').value = trace.request.url || '';
  $('repHeaders').value = JSON.stringify(trace.request.headers || {}, null, 2);
  $('repBody').value = trace.request.body || '';

  if (trace.request.oauthParams?.redirect_uri) {
    refreshRedirectMutations(trace.request.oauthParams.redirect_uri);
  }
  refreshCustomParamOptions();
  renderAudit(trace.audit);
}

export function renderJwtCard(label, insp) {
  return `
    <div class="jwt-card">
      <div class="finding-head">
        <span class="badge badge-info">${escapeHtml(label)}</span>
        <span class="mono" style="font-size:11px;">alg: ${escapeHtml(insp.header?.alg || '?')}</span>
        ${insp.expiresAt ? `<span class="muted">exp: ${escapeHtml(insp.expiresAt)}</span>` : ''}
      </div>
      <div class="pane-subtitle">Header</div>
      <pre class="code-block">${escapeHtml(JSON.stringify(insp.header, null, 2))}</pre>
      <div class="pane-subtitle">Payload</div>
      <pre class="code-block">${escapeHtml(JSON.stringify(insp.payload, null, 2))}</pre>
    </div>
  `;
}

export function renderAudit(audit) {
  const findingsEl = $('auditFindings');
  const jwtEl = $('jwtList');
  const badge = $('auditTabBadge');
  if (!audit) {
    badge.textContent = '0';
    badge.className = 'badge badge-muted';
    findingsEl.textContent = 'No audit data.';
    jwtEl.innerHTML = '';
    return;
  }

  const fCount = (audit.findings || []).length;
  const jCount = (audit.jwts || []).length;
  badge.textContent = String(fCount + jCount);
  const hasHigh = (audit.findings || []).some((f) => f.severity === 'HIGH');
  badge.className = `badge ${hasHigh ? 'badge-danger' : fCount > 0 ? 'badge-warn' : 'badge-muted'}`;

  if (fCount === 0) {
    findingsEl.innerHTML = '<div class="muted">No security issues flagged for this trace.</div>';
  } else {
    findingsEl.innerHTML = audit.findings
      .map(
        (f) => `
      <div class="finding-card">
        <div class="finding-head">
          <span class="badge ${severityBadgeClass(f.severity)}">${escapeHtml(f.severity)}</span>
          <span>${escapeHtml(f.title)}</span>
        </div>
        <div class="finding-detail">${escapeHtml(f.detail)}</div>
      </div>`
      )
      .join('');
  }

  if (jCount === 0) {
    jwtEl.innerHTML = '<div class="muted">No JWTs detected in this trace.</div>';
  } else {
    jwtEl.innerHTML = audit.jwts.map((j) => renderJwtCard(j.label, j.inspection)).join('');
  }
}

export function renderSequenceDiagram() {
  const container = $('sequenceDiagram');
  const selected = state.traces.find((t) => t.id === state.selectedTraceId);
  if (!selected) {
    $('diagramSubtitle').textContent = 'Select a trace or run a flow';
    container.innerHTML = '<div class="muted">No active trace group.</div>';
    return;
  }

  let group = state.traces
    .filter((t) => t.traceGroupId === selected.traceGroupId)
    .slice()
    .reverse();
  if (group.length === 1 && state.traces.length > 1) {
    group = state.traces.slice(0, 6).reverse();
  }

  $('diagramSubtitle').textContent = `${group.length} HTTP step(s)`;

  const actors = ['Client / Workbench', 'Authorization Server', 'Callback / Redirect', 'Token / Resource'];
  const colX = [100, 320, 540, 760];
  const width = 880;
  const rowH = 38;
  const height = 46 + group.length * rowH + 20;

  let svg = `<svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMin meet" style="max-width:1150px; display:block; margin:0 auto;" xmlns="http://www.w3.org/2000/svg">`;
  svg += `<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/></marker></defs>`;

  actors.forEach((name, idx) => {
    const x = colX[idx];
    svg += `<rect x="${x - 75}" y="6" width="150" height="24" rx="4" fill="#1e293b" stroke="#334155"/>`;
    svg += `<text x="${x}" y="22" text-anchor="middle" fill="#e2e8f0" font-size="11" font-family="sans-serif" font-weight="600">${escapeHtml(name)}</text>`;
    svg += `<line x1="${x}" y1="30" x2="${x}" y2="${height - 10}" stroke="#2c3a4f" stroke-dasharray="4 3"/>`;
  });

  group.forEach((t, i) => {
    const y = 54 + i * rowH;
    const url = t.request.url || '';
    let fromIdx = 0;
    let toIdx = 1;
    if (/\/token|\/userinfo|jwks/i.test(url)) {
      fromIdx = 0;
      toIdx = 3;
    } else if (/\/callback/i.test(url)) {
      fromIdx = 1;
      toIdx = 2;
    }

    const x1 = colX[fromIdx];
    const x2 = colX[toIdx];
    const midX = (x1 + x2) / 2;
    const rawPath = (() => {
      try { return new URL(url).pathname; } catch { return url; }
    })();
    const path = rawPath.length > 28 ? `${rawPath.slice(0, 25)}...` : rawPath;
    const isSelected = t.id === state.selectedTraceId;
    const stroke = isSelected ? '#38bdf8' : '#64748b';
    const textColor = isSelected ? '#f8fafc' : '#94a3b8';

    svg += `<g class="seq-step" data-trace-id="${t.id}" style="cursor:pointer;">`;
    svg += `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="${stroke}" stroke-width="${isSelected ? 2 : 1.5}" marker-end="url(#arrow)"/>`;
    svg += `<text x="${midX}" y="${y - 6}" text-anchor="middle" fill="${textColor}" font-size="11" font-family="monospace">${escapeHtml(`${t.request.method} ${path} [${t.response.status}]`)}</text>`;
    svg += `</g>`;
  });

  svg += '</svg>';
  container.innerHTML = svg;

  container.querySelectorAll('.seq-step').forEach((g) => {
    g.addEventListener('click', () => {
      state.selectedTraceId = g.dataset.traceId;
      renderTraceList();
      renderSelectedTrace();
      renderSequenceDiagram();
    });
  });
}
