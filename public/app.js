const state = {
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

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  return res.json();
}

function statusBadgeClass(status) {
  if (!status) return 'badge-muted';
  if (status >= 200 && status < 300) return 'badge-ok';
  if (status >= 300 && status < 400) return 'badge-info';
  if (status >= 400 && status < 500) return 'badge-warn';
  return 'badge-danger';
}

function severityBadgeClass(sev) {
  if (sev === 'HIGH') return 'badge-danger';
  if (sev === 'MEDIUM') return 'badge-warn';
  if (sev === 'LOW') return 'badge-info';
  return 'badge-muted';
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function loadTraces() {
  const data = await api('/api/traces');
  state.traces = data.traces || [];
  if (!state.selectedTraceId && state.traces.length > 0) {
    state.selectedTraceId = state.traces[0].id;
  }
  renderTraceList();
  renderSelectedTrace();
  renderSequenceDiagram();
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

function renderTraceList() {
  $('traceCount').textContent = String(state.traces.length);
  const container = $('traceList');
  if (state.traces.length === 0) {
    container.innerHTML = '<div class="muted" style="padding:12px;">No traces yet. Run Demo Flow or send a request.</div>';
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
            <button class="trace-expand-btn" data-id="${t.id}" title="Expand / collapse details">${expanded ? '▾' : '▸'}</button>
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

async function refreshCookieJarBadge() {
  const data = await api('/api/cookies');
  $('cookieJarBadge').textContent = `Cookies: ${(data.cookies || []).length}`;
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

function renderSelectedTrace() {
  const trace = state.traces.find((t) => t.id === state.selectedTraceId);
  if (!trace) return;

  renderDiffBanner(trace);
  $('reqSummary').textContent = `${trace.request.method} ${trace.request.url}`;
  renderKvTable($('reqOAuthParams'), trace.request.oauthParams || {});
  renderKvTable($('reqHeaders'), trace.request.headers || {});
  $('reqBody').textContent = trace.request.body || '(empty)';

  $('resStatusBadge').innerHTML = `<span class="badge ${statusBadgeClass(trace.response.status)}">${trace.response.status} ${escapeHtml(trace.response.statusText || '')}</span>`;
  $('resSummary').textContent = trace.response.location
    ? `HTTP ${trace.response.status} -> Location: ${trace.response.location}`
    : `HTTP ${trace.response.status} (${trace.durationMs}ms)`;
  renderKvTable($('resOAuthParams'), trace.response.oauthParams || {});
  renderCookiesTable($('resCookies'), trace.response.cookies || []);
  renderKvTable($('resHeaders'), trace.response.headers || {});
  $('resBody').textContent = formatBody(trace.response.body);

  // Sync into Repeater if URL is present
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

function formatBody(body) {
  if (!body) return '(empty)';
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function renderAudit(audit) {
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

  if (!audit.findings || audit.findings.length === 0) {
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

  if (!audit.jwts || audit.jwts.length === 0) {
    jwtEl.innerHTML = '<div class="muted">No JWTs detected in this trace.</div>';
  } else {
    jwtEl.innerHTML = audit.jwts.map((j) => renderJwtCard(j.label, j.inspection)).join('');
  }
}

function renderJwtCard(label, insp) {
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

function renderSequenceDiagram() {
  const container = $('sequenceDiagram');
  const selected = state.traces.find((t) => t.id === state.selectedTraceId);
  if (!selected) {
    $('diagramSubtitle').textContent = 'Select a trace or run a flow';
    container.innerHTML = '<div class="muted">No active trace group.</div>';
    return;
  }

  // Collect all traces in same traceGroupId (chronological) or fallback to recent 6
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
    } else if (/well-known/i.test(url)) {
      fromIdx = 0;
      toIdx = 1;
    }

    const x1 = colX[fromIdx];
    const x2 = colX[toIdx];
    const midX = (x1 + x2) / 2;
    const path = (() => {
      try { return new URL(url).pathname; } catch { return url; }
    })();
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

async function refreshRedirectMutations(baseRedirectUri) {
  const attackerHost = $('attackerHostInput').value.trim() || 'attacker.example';
  const uri = baseRedirectUri || extractRedirectFromRepeater() || 'http://localhost:3000/callback';
  const data = await api('/api/mutations/redirect-uri', {
    method: 'POST',
    body: JSON.stringify({ baseRedirectUri: uri, attackerHost }),
  });
  state.redirectMutations = data.mutations || [];
  renderRedirectMutations();
}

function extractRedirectFromRepeater() {
  try {
    return new URL($('repUrl').value).searchParams.get('redirect_uri');
  } catch {
    return null;
  }
}

function renderRedirectMutations() {
  const wrap = $('redirectMutationList');
  const summaryEl = $('redirectFuzzerSummary');
  const onlyAccepted = $('redirectOnlyAccepted')?.checked;

  if (state.redirectMutations.length === 0) {
    wrap.innerHTML = '<div class="muted">Click Generate to build redirect_uri payloads.</div>';
    return;
  }

  if (state.batchResults.size > 0) {
    const all = [...state.batchResults.values()];
    const acc = all.filter((r) => r.accepted).length;
    summaryEl.innerHTML = `${all.length} probed · <span style="color:${acc ? '#f87171' : '#4ade80'}">${acc} ACCEPTED</span> · ${all.length - acc} blocked`;
  } else {
    summaryEl.textContent = `${state.redirectMutations.length} payloads ready.`;
  }

  const list = onlyAccepted
    ? state.redirectMutations.filter((m) => state.batchResults.get(m.id)?.accepted)
    : state.redirectMutations;

  const rows = list
    .map((m) => {
      const res = state.batchResults.get(m.id);
      const badgeCls = !res ? '' : res.accepted ? 'badge-danger' : res.verdict === 'REDIRECT_ERROR' ? 'badge-warn' : 'badge-ok';
      const statusCell = res
        ? `<span class="badge ${badgeCls}">${escapeHtml(res.verdict || (res.accepted ? 'ACCEPTED' : 'BLOCKED'))} (${res.status})</span>`
        : '<span class="muted">-</span>';
      return `
        <tr>
          <td><span class="badge badge-muted">${escapeHtml(m.category)}</span></td>
          <td>
            <div style="font-weight:600;">${escapeHtml(m.label)}</div>
            <div class="mono muted" style="word-break:break-all;">${escapeHtml(m.uri)}</div>
          </td>
          <td>${statusCell}</td>
          <td><button class="btn btn-secondary use-mut-btn" data-uri="${escapeHtml(m.uri)}">Load</button></td>
        </tr>
      `;
    })
    .join('');

  wrap.innerHTML = `
    <table class="mut-table">
      <thead><tr><th>Category</th><th>Payload</th><th>Probe Result</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;

  wrap.querySelectorAll('.use-mut-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      try {
        const u = new URL($('repUrl').value);
        u.searchParams.set('redirect_uri', btn.dataset.uri);
        $('repUrl').value = u.toString();
      } catch {
        $('repUrl').value = btn.dataset.uri;
      }
    });
  });
}

async function loadParamMutations() {
  const res = await api('/api/parse', {
    method: 'POST',
    body: JSON.stringify({ input: 'https://example.com/authorize?client_id=demo&response_type=code' }),
  });
  state.paramMutations = res.paramMutations || [];

  const sel = $('quickMutateSelect');
  if (sel) {
    const authOpts = state.paramMutations
      .map((m) => `<option value="auth:${escapeHtml(m.id)}" title="${escapeHtml(m.description)}">${escapeHtml(m.label)}</option>`)
      .join('');
    sel.innerHTML = `
      <option value="">Quick Mutate...</option>
      <optgroup label="Authorize Parameters">${authOpts}</optgroup>
      <optgroup label="Token Endpoint Body (POST)">
        <option value="tok:strip_verifier" title="Remove code_verifier from POST body to test if /token enforces PKCE.">Strip code_verifier</option>
        <option value="tok:mismatch_redirect" title="Replace redirect_uri in POST body with attacker URI to test redirect_uri binding.">Mismatch redirect_uri</option>
        <option value="tok:drop_redirect" title="Remove redirect_uri from POST body.">Drop redirect_uri</option>
      </optgroup>
    `;
  }

  renderParamFuzzerTable();
}

function applyParamPatchToRepeater(patch) {
  try {
    const u = new URL($('repUrl').value);
    for (const [k, v] of Object.entries(patch)) {
      if (k === 'scope_append') {
        const cur = u.searchParams.get('scope') || 'openid';
        u.searchParams.set('scope', `${cur} ${v}`.trim());
      } else if (v === null) {
        u.searchParams.delete(k);
      } else {
        u.searchParams.set(k, v);
      }
    }
    $('repUrl').value = u.toString();
  } catch {
    // Ignore if repeater URL is not valid yet
  }
}

function renderParamFuzzerTable() {
  const wrap = $('paramFuzzerList');
  const summaryEl = $('paramFuzzerSummary');
  const onlyAccepted = $('paramOnlyAccepted')?.checked;

  if (!state.paramMutations.length) {
    wrap.innerHTML = '<div class="muted">No parameter probes loaded.</div>';
    return;
  }

  if (state.paramBatchResults.size > 0) {
    const all = [...state.paramBatchResults.values()];
    const acc = all.filter((r) => r.accepted).length;
    summaryEl.innerHTML = `${all.length} probed · <span style="color:${acc ? '#f87171' : '#4ade80'}">${acc} ACCEPTED (RISK)</span> · ${all.length - acc} blocked`;
  } else {
    summaryEl.textContent = `${state.paramMutations.length} probes ready.`;
  }

  const list = onlyAccepted
    ? state.paramMutations.filter((m) => state.paramBatchResults.get(m.id)?.accepted)
    : state.paramMutations;

  const rows = list
    .map((m) => {
      const res = state.paramBatchResults.get(m.id);
      const badgeCls = !res ? '' : res.accepted ? 'badge-danger' : res.verdict === 'REDIRECT_ERROR' ? 'badge-warn' : 'badge-ok';
      const statusCell = res
        ? `<span class="badge ${badgeCls}">${escapeHtml(res.verdict)} (${res.status})</span>`
        : '<span class="muted">-</span>';
      return `
        <tr>
          <td>
            <div style="font-weight:600;">${escapeHtml(m.label)}</div>
            <div class="muted">${escapeHtml(m.description)}</div>
          </td>
          <td>${statusCell}</td>
          <td><button class="btn btn-secondary use-param-mut-btn" data-patch='${escapeHtml(JSON.stringify(m.patch))}'>Load</button></td>
        </tr>
      `;
    })
    .join('');
  wrap.innerHTML = `
    <table class="mut-table">
      <thead><tr><th>Probe</th><th>Result</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
  wrap.querySelectorAll('.use-param-mut-btn').forEach((btn) => {
    btn.addEventListener('click', () => applyParamPatchToRepeater(JSON.parse(btn.dataset.patch)));
  });
}

async function loadMockConfig() {
  const cfg = await api('/mock-idp/config');
  document.querySelectorAll('#mockToggles input[type="checkbox"]').forEach((cb) => {
    cb.checked = Boolean(cfg[cb.dataset.key]);
    cb.onchange = async () => {
      await api('/mock-idp/config', {
        method: 'POST',
        body: JSON.stringify({ [cb.dataset.key]: cb.checked }),
      });
    };
  });
}

// Event listeners
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach((c) => c.classList.remove('active'));
    tab.classList.add('active');
    $(`tab-${tab.dataset.tab}`).classList.add('active');
  });
});

$('discoverBtn').addEventListener('click', async () => {
  const issuerUrl = $('issuerInput').value.trim();
  if (!issuerUrl) return;
  const data = await api('/api/discover', { method: 'POST', body: JSON.stringify({ issuerUrl }) });
  renderDiscovery(data);
  document.querySelector('[data-tab="discovery"]').click();
  await loadTraces();
});

function renderDiscovery(data) {
  const container = $('discoveryStructured');
  const rawDetails = $('discoveryRawDetails');
  const copyJsonBtn = $('copyDiscoveryJsonBtn');

  if (!data || data.error || !data.summary) {
    container.innerHTML = `<div class="finding-card"><span class="badge badge-warn">ERROR</span> ${escapeHtml(data?.error || 'Discovery failed')}</div>`;
    rawDetails.style.display = 'none';
    copyJsonBtn.style.display = 'none';
    return;
  }

  const s = data.summary;
  if (s.jwks_uri && $('jwksUriInput')) {
    $('jwksUriInput').value = s.jwks_uri;
  }
  rawDetails.style.display = 'block';
  copyJsonBtn.style.display = 'inline-block';
  $('discoveryOutput').textContent = JSON.stringify(data.raw || data, null, 2);
  copyJsonBtn.onclick = () => copyToClipboard(JSON.stringify(data.raw || data, null, 2), 'Copied Discovery JSON');

  const rt = s.response_types_supported || [];
  const pkce = s.code_challenge_methods_supported || [];
  const scopes = s.scopes_supported || [];
  const authMethods = s.token_endpoint_auth_methods_supported || [];

  const hasImplicit = rt.some((r) => r.split(/\s+/).includes('token'));
  const hasPlainPkce = pkce.includes('plain');

  const endpointRows = [
    ['Issuer', s.issuer, 'issuer'],
    ['Authorization Endpoint', s.authorization_endpoint, 'authorize'],
    ['Token Endpoint', s.token_endpoint, 'token'],
    ['UserInfo Endpoint', s.userinfo_endpoint, 'userinfo'],
    ['JWKS URI', s.jwks_uri, 'jwks'],
    ['End Session (Logout)', s.end_session_endpoint, 'logout'],
    ['Revocation Endpoint', s.revocation_endpoint, 'revoke'],
    ['Introspection Endpoint', s.introspection_endpoint, 'introspect'],
  ]
    .filter(([, url]) => Boolean(url))
    .map(([label, url, kind]) => {
      let actionBtn = '';
      if (kind === 'authorize') {
        actionBtn = `<button class="btn btn-primary disc-load-auth" data-url="${escapeHtml(url)}">Build Auth -&gt; Repeater</button>`;
      } else if (kind === 'token') {
        actionBtn = `<button class="btn btn-secondary disc-load-token" data-url="${escapeHtml(url)}">Load POST -&gt; Repeater</button>`;
      } else if (kind === 'userinfo' || kind === 'jwks') {
        actionBtn = `<button class="btn btn-secondary disc-load-get" data-url="${escapeHtml(url)}">Load GET -&gt; Repeater</button>`;
      }
      return `
        <tr>
          <td>${escapeHtml(label)}</td>
          <td class="mono">${escapeHtml(url)}</td>
          <td>
            <div class="disc-actions">
              <button class="btn btn-ghost disc-copy-url" data-url="${escapeHtml(url)}">Copy</button>
              ${actionBtn}
            </div>
          </td>
        </tr>
      `;
    })
    .join('');

  container.innerHTML = `
    <div class="disc-grid">
      <div class="disc-stat">
        <div class="disc-stat-label">Response Types</div>
        <div>${rt.map((t) => `<span class="badge ${t.includes('token') ? 'badge-warn' : 'badge-ok'}" style="margin:2px;">${escapeHtml(t)}</span>`).join('') || '<span class="muted">not listed</span>'}</div>
        ${hasImplicit ? '<div class="muted" style="margin-top:4px;color:#fbbf24;">Implicit/token flow enabled</div>' : ''}
      </div>
      <div class="disc-stat">
        <div class="disc-stat-label">PKCE Methods</div>
        <div>${pkce.map((m) => `<span class="badge ${m === 'plain' ? 'badge-warn' : 'badge-ok'}" style="margin:2px;">${escapeHtml(m)}</span>`).join('') || '<span class="muted">not advertised</span>'}</div>
        ${hasPlainPkce ? '<div class="muted" style="margin-top:4px;color:#fbbf24;">PKCE plain downgrade allowed</div>' : ''}
      </div>
      <div class="disc-stat">
        <div class="disc-stat-label">Token Auth Methods</div>
        <div>${authMethods.map((a) => `<span class="badge badge-info" style="margin:2px;">${escapeHtml(a)}</span>`).join('') || '<span class="muted">not listed</span>'}</div>
      </div>
      <div class="disc-stat">
        <div class="disc-stat-label">Supported Scopes (${scopes.length})</div>
        <div>${scopes.map((sc) => `<span class="badge badge-muted disc-copy-scope" data-scope="${escapeHtml(sc)}" style="margin:2px;cursor:pointer;" title="Click to copy">${escapeHtml(sc)}</span>`).join('') || '<span class="muted">not listed</span>'}</div>
      </div>
    </div>

    <div class="pane-subtitle" style="margin-top:10px;">Discovered Endpoints</div>
    <div class="kv-wrap" style="max-height:none;">
      <table class="kv-table">
        <tbody>${endpointRows}</tbody>
      </table>
    </div>
  `;

  container.querySelectorAll('.disc-copy-url').forEach((btn) => {
    btn.addEventListener('click', () => copyToClipboard(btn.dataset.url, 'Copied URL'));
  });
  container.querySelectorAll('.disc-copy-scope').forEach((el) => {
    el.addEventListener('click', () => copyToClipboard(el.dataset.scope, `Copied scope: ${el.dataset.scope}`));
  });
  container.querySelectorAll('.disc-load-auth').forEach((btn) => {
    btn.addEventListener('click', () => {
      const u = new URL(btn.dataset.url);
      u.searchParams.set('client_id', 'demo-client');
      u.searchParams.set('redirect_uri', `${window.location.origin}/callback`);
      u.searchParams.set('response_type', 'code');
      u.searchParams.set('scope', scopes.includes('openid') ? 'openid profile email' : (scopes[0] || 'openid'));
      u.searchParams.set('state', randomToken(16));
      $('repMethod').value = 'GET';
      $('repUrl').value = u.toString();
      $('repHeaders').value = '{}';
      $('repBody').value = '';
      refreshRedirectMutations(`${window.location.origin}/callback`);
      document.querySelector('[data-tab="repeater"]').click();
    });
  });
  container.querySelectorAll('.disc-load-token').forEach((btn) => {
    btn.addEventListener('click', () => {
      $('repMethod').value = 'POST';
      $('repUrl').value = btn.dataset.url;
      $('repHeaders').value = JSON.stringify({ 'Content-Type': 'application/x-www-form-urlencoded' }, null, 2);
      $('repBody').value = new URLSearchParams({
        grant_type: 'authorization_code',
        code: 'PASTE_CODE_HERE',
        redirect_uri: `${window.location.origin}/callback`,
        client_id: 'demo-client',
      }).toString();
      document.querySelector('[data-tab="repeater"]').click();
    });
  });
  container.querySelectorAll('.disc-load-get').forEach((btn) => {
    btn.addEventListener('click', () => {
      $('repMethod').value = 'GET';
      $('repUrl').value = btn.dataset.url;
      $('repHeaders').value = btn.dataset.url.includes('userinfo')
        ? JSON.stringify({ Authorization: 'Bearer PASTE_ACCESS_TOKEN' }, null, 2)
        : '{}';
      $('repBody').value = '';
      document.querySelector('[data-tab="repeater"]').click();
    });
  });
}

$('demoFlowBtn').addEventListener('click', async () => {
  const base = window.location.origin;
  const authUrl = `${base}/mock-idp/authorize?client_id=demo-client&redirect_uri=${encodeURIComponent(`${base}/callback`)}&response_type=code&scope=openid%20profile%20email&state=demo_state_123456`;
  const authRes = await api('/api/send', {
    method: 'POST',
    body: JSON.stringify({ method: 'GET', url: authUrl, followRedirects: true, label: 'demo_authorize_flow' }),
  });

  const callbackHop = (authRes.hops || []).find((h) => h.response?.oauthParams?.code);
  if (callbackHop) {
    const code = callbackHop.response.oauthParams.code;
    const tokenRes = await api('/api/send', {
      method: 'POST',
      body: JSON.stringify({
        method: 'POST',
        url: `${base}/mock-idp/token`,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: `${base}/callback`,
          client_id: 'demo-client',
        }).toString(),
        label: 'demo_token_exchange',
      }),
    });

    const tokenBody = tokenRes.hops?.[0]?.response?.body;
    if (tokenBody) {
      try {
        const parsed = JSON.parse(tokenBody);
        if (parsed.access_token) {
          await api('/api/send', {
            method: 'POST',
            body: JSON.stringify({
              method: 'GET',
              url: `${base}/mock-idp/userinfo`,
              headers: { Authorization: `Bearer ${parsed.access_token}` },
              label: 'demo_userinfo',
            }),
          });
        }
      } catch {
        // Ignore
      }
    }
  }

  state.selectedTraceId = null;
  await loadTraces();
});

$('clearTracesBtn').addEventListener('click', async () => {
  await api('/api/traces', { method: 'DELETE' });
  state.selectedTraceId = null;
  state.batchResults.clear();
  await loadTraces();
});

$('pasteParseBtn').addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (text) {
      $('parseInput').value = text;
      $('parseBtn').click();
    }
  } catch {
    $('parseInput').focus();
  }
});

$('parseBtn').addEventListener('click', async () => {
  const input = $('parseInput').value.trim();
  if (!input) return;
  const data = await api('/api/parse', { method: 'POST', body: JSON.stringify({ input }) });
  if (data.error) {
    alert(data.error);
    return;
  }
  $('repMethod').value = data.parsed.method || 'GET';
  $('repUrl').value = data.parsed.url || '';
  $('repHeaders').value = JSON.stringify(data.parsed.headers || {}, null, 2);
  $('repBody').value = data.parsed.body || '';
  state.redirectMutations = data.redirectMutations || [];
  renderRedirectMutations();
  refreshCustomParamOptions();
  renderAudit(data.audit);
  document.querySelector('[data-tab="repeater"]').click();
});

$('repSendBtn').addEventListener('click', async () => {
  let headers = {};
  try { headers = JSON.parse($('repHeaders').value || '{}'); } catch { headers = {}; }
  const data = await api('/api/send', {
    method: 'POST',
    body: JSON.stringify({
      method: $('repMethod').value,
      url: $('repUrl').value.trim(),
      headers,
      body: $('repBody').value,
      followRedirects: $('repFollowRedirects').checked,
      useCookieJar: $('repUseCookieJar').checked,
      label: 'repeater',
    }),
  });
  if (data.hops && data.hops.length > 0) {
    state.selectedTraceId = data.hops[0].id;
    const last = data.hops[data.hops.length - 1];
    const locLine = last.response.location ? `\nLocation: ${last.response.location}` : '';
    const bodyPreview = (last.response.body || '').slice(0, 1200);
    $('repResponsePreview').textContent = `HTTP ${last.response.status} ${last.response.statusText || ''} (${last.durationMs}ms)${locLine}\n\n${bodyPreview || '(empty body)'}`;
    const resBadge = $('repResTabBadge');
    resBadge.textContent = String(last.response.status || 'ERR');
    resBadge.className = `badge ${statusBadgeClass(last.response.status)}`;
    document.querySelector('.rep-subtab[data-reptab="response"]').click();
  }
  await refreshCookieJarBadge();
  await loadTraces();
});

$('redirectOnlyAccepted').addEventListener('change', renderRedirectMutations);
$('paramOnlyAccepted').addEventListener('change', renderParamFuzzerTable);
$('customOnlyAnomalies').addEventListener('change', renderCustomFuzzerTable);

function refreshCustomParamOptions() {
  const sel = $('customParamSelect');
  if (!sel) return;
  const opts = ['<option value="">-- Custom --</option>'];

  try {
    const u = new URL($('repUrl').value.trim());
    for (const k of new Set(u.searchParams.keys())) {
      opts.push(`<option value="query:${escapeHtml(k)}">query: ${escapeHtml(k)}</option>`);
    }
  } catch {
    // Ignore invalid URL
  }

  const body = ($('repBody').value || '').trim();
  if (body) {
    try {
      const jsonObj = JSON.parse(body);
      if (jsonObj && typeof jsonObj === 'object' && !Array.isArray(jsonObj)) {
        for (const k of Object.keys(jsonObj)) {
          opts.push(`<option value="body:${escapeHtml(k)}">body: ${escapeHtml(k)}</option>`);
        }
      }
    } catch {
      const sp = new URLSearchParams(body);
      for (const k of new Set(sp.keys())) {
        opts.push(`<option value="body:${escapeHtml(k)}">body: ${escapeHtml(k)}</option>`);
      }
    }
  }

  sel.innerHTML = opts.join('');
}

async function loadCustomPresets() {
  const data = await api('/api/mutations/custom-presets');
  state.customPresets = data.presets || [];
  const sel = $('customPresetSelect');
  sel.innerHTML = `<option value="">Load Payload Preset...</option>${state.customPresets
    .map((p) => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.label)} (${p.payloads.length})</option>`)
    .join('')}`;
  if (state.customPresets[0] && !$('customPayloadsInput').value.trim()) {
    $('customPayloadsInput').value = state.customPresets[0].payloads.join('\n');
  }
}

$('customParamSelect').addEventListener('change', (e) => {
  const val = e.target.value;
  if (!val) return;
  const idx = val.indexOf(':');
  const loc = val.slice(0, idx);
  const name = val.slice(idx + 1);
  $('customTargetLoc').value = loc;
  $('customParamInput').value = name;
});

$('customPresetSelect').addEventListener('change', (e) => {
  const preset = state.customPresets.find((p) => p.id === e.target.value);
  if (preset) {
    $('customPayloadsInput').value = preset.payloads.join('\n');
  }
  e.target.value = '';
});

$('repUrl').addEventListener('change', refreshCustomParamOptions);
$('repBody').addEventListener('change', refreshCustomParamOptions);

function renderCustomFuzzerTable() {
  const wrap = $('customFuzzerList');
  const summaryEl = $('customFuzzerSummary');
  const data = state.customBatchData;
  if (!data || !data.results) {
    wrap.innerHTML = '<div class="muted">No custom fuzzing results yet.</div>';
    return;
  }

  const anomCount = data.results.filter((r) => r.anomaly).length;
  summaryEl.innerHTML = `Baseline HTTP ${data.baseline.status} (${data.baseline.bodyLen}B) · ${data.results.length} tested · <span style="color:${anomCount ? '#fbbf24' : '#4ade80'}">${anomCount} ANOMALIES</span>`;

  const onlyAnom = $('customOnlyAnomalies').checked;
  const list = onlyAnom ? data.results.filter((r) => r.anomaly) : data.results;

  wrap.innerHTML = `
    <table class="mut-table">
      <thead><tr><th>Payload</th><th>Status</th><th>Delta</th><th>Verdict</th><th></th></tr></thead>
      <tbody>
        ${list
          .map(
            (r) => `
          <tr>
            <td class="mono" style="word-break:break-all;">${escapeHtml(r.payload === '' ? '(empty)' : r.payload)}</td>
            <td class="mono">${r.status}</td>
            <td class="mono">${r.lenDelta >= 0 ? '+' : ''}${r.lenDelta}B</td>
            <td><span class="badge ${r.anomaly ? 'badge-warn' : 'badge-muted'}">${escapeHtml(r.verdict)}</span></td>
            <td><button class="btn btn-secondary use-custom-payload-btn" data-payload="${escapeHtml(r.payload)}">Load</button></td>
          </tr>
        `
          )
          .join('')}
      </tbody>
    </table>
  `;

  wrap.querySelectorAll('.use-custom-payload-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const name = $('customParamInput').value.trim();
      const loc = $('customTargetLoc').value;
      const payload = btn.dataset.payload;
      if (!name) return;
      if (loc === 'body') {
        mutateTokenBody((p) => p.set(name, payload));
      } else {
        try {
          const u = new URL($('repUrl').value);
          u.searchParams.set(name, payload);
          $('repUrl').value = u.toString();
        } catch {
          // Ignore
        }
      }
    });
  });
}

$('batchCustomBtn').addEventListener('click', async () => {
  const baseUrl = $('repUrl').value.trim();
  const paramName = $('customParamInput').value.trim();
  const targetLocation = $('customTargetLoc').value;
  const payloads = $('customPayloadsInput')
    .value.split('\n')
    .map((s) => s.replace(/\r$/, ''));
  if (!baseUrl || !paramName || payloads.length === 0) return;

  let headers = {};
  try { headers = JSON.parse($('repHeaders').value || '{}'); } catch { headers = {}; }

  const data = await api('/api/mutations/custom/batch', {
    method: 'POST',
    body: JSON.stringify({
      method: $('repMethod').value,
      baseUrl,
      headers,
      body: $('repBody').value,
      targetLocation,
      paramName,
      payloads,
      useCookieJar: $('repUseCookieJar').checked,
    }),
  });
  state.customBatchData = data;
  renderCustomFuzzerTable();
  await loadTraces();
});

$('clearCookiesBtn').addEventListener('click', async () => {
  await api('/api/cookies', { method: 'DELETE' });
  await refreshCookieJarBadge();
});

$('refreshMutationsBtn').addEventListener('click', () => refreshRedirectMutations());

$('repOpenBrowserBtn').addEventListener('click', () => {
  const url = $('repUrl').value.trim();
  if (!url) return;
  window.open(url, '_blank', 'noopener');
});

$('repReplay2xBtn').addEventListener('click', async () => {
  let headers = {};
  try { headers = JSON.parse($('repHeaders').value || '{}'); } catch { headers = {}; }
  const payload = {
    method: $('repMethod').value,
    url: $('repUrl').value.trim(),
    headers,
    body: $('repBody').value,
    followRedirects: $('repFollowRedirects').checked,
    useCookieJar: $('repUseCookieJar').checked,
    label: 'replay_2x',
  };
  if (!payload.url) return;
  const r1 = await api('/api/send', { method: 'POST', body: JSON.stringify(payload) });
  const r2 = await api('/api/send', { method: 'POST', body: JSON.stringify(payload) });
  const s1 = r1.hops?.[0]?.response?.status ?? 'ERR';
  const s2 = r2.hops?.[0]?.response?.status ?? 'ERR';
  $('replayResultBox').style.display = 'block';
  $('replayResultBox').textContent = `Replay 2x -> Attempt #1: HTTP ${s1} | Attempt #2: HTTP ${s2}`;
  await refreshCookieJarBadge();
  await loadTraces();
});

function mutateTokenBody(mutator) {
  const params = new URLSearchParams($('repBody').value || '');
  mutator(params);
  $('repBody').value = params.toString();
}

$('quickMutateSelect').addEventListener('change', (e) => {
  const val = e.target.value;
  if (!val) return;
  if (val.startsWith('auth:')) {
    const id = val.slice(5);
    const mut = state.paramMutations.find((m) => m.id === id);
    if (mut) applyParamPatchToRepeater(mut.patch);
  } else if (val === 'tok:strip_verifier') {
    mutateTokenBody((p) => p.delete('code_verifier'));
  } else if (val === 'tok:mismatch_redirect') {
    const host = $('attackerHostInput').value.trim() || 'attacker.example';
    mutateTokenBody((p) => p.set('redirect_uri', `https://${host}/callback`));
  } else if (val === 'tok:drop_redirect') {
    mutateTokenBody((p) => p.delete('redirect_uri'));
  }
  e.target.value = '';
});

document.querySelectorAll('.rep-subtab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.rep-subtab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.rep-subpanel').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    $(`reptab-${tab.dataset.reptab}`).classList.add('active');
  });
});

document.querySelectorAll('.fuzzer-tab:not(.rep-subtab)').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.fuzzer-tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.fuzzer-panel').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    $(`fuzzer-${tab.dataset.fuzzer}`).classList.add('active');
  });
});

$('batchParamsBtn').addEventListener('click', async () => {
  const baseUrl = $('repUrl').value.trim();
  if (!baseUrl) return;
  const useCookieJar = $('repUseCookieJar').checked;
  const data = await api('/api/mutations/params/batch', {
    method: 'POST',
    body: JSON.stringify({ baseUrl, useCookieJar }),
  });
  state.paramBatchResults.clear();
  for (const r of data.results || []) {
    state.paramBatchResults.set(r.id, r);
  }
  renderParamFuzzerTable();
  await loadTraces();
});

$('batchRedirectBtn').addEventListener('click', async () => {
  const baseUrl = $('repUrl').value.trim();
  if (!baseUrl) return;
  const attackerHost = $('attackerHostInput').value.trim() || 'attacker.example';
  const useCookieJar = $('repUseCookieJar').checked;
  const data = await api('/api/mutations/redirect-uri/batch', {
    method: 'POST',
    body: JSON.stringify({ baseUrl, attackerHost, useCookieJar }),
  });
  state.batchResults.clear();
  for (const r of data.results || []) {
    state.batchResults.set(r.id, r);
  }
  renderRedirectMutations();
  await loadTraces();
});

$('inspectJwtBtn').addEventListener('click', async () => {
  const token = $('manualJwtInput').value.trim();
  if (!token) return;
  const insp = await api('/api/jwt/inspect', { method: 'POST', body: JSON.stringify({ token }) });
  if (insp.valid) {
    $('jwtList').innerHTML = renderJwtCard('manual', insp);
  } else {
    $('jwtList').innerHTML = `<div class="finding-card">${escapeHtml(insp.error || 'Invalid JWT')}</div>`;
  }
});

$('verifyJwtBtn').addEventListener('click', async () => {
  let token = $('manualJwtInput').value.trim();
  if (!token) {
    const trace = state.traces.find((t) => t.id === state.selectedTraceId);
    token = trace?.audit?.jwts?.[0]?.token || '';
  }
  const jwksUri = $('jwksUriInput').value.trim();
  const outEl = $('jwtVerifyResult');
  if (!token || !jwksUri) {
    outEl.style.display = 'block';
    outEl.innerHTML = '<span class="badge badge-warn">Provide both a JWT (or select a trace with one) and a JWKS URI.</span>';
    return;
  }
  const res = await api('/api/jwt/verify', {
    method: 'POST',
    body: JSON.stringify({ token, jwksUri }),
  });
  outEl.style.display = 'block';
  outEl.innerHTML = `<span class="badge ${res.verified ? 'badge-ok' : 'badge-danger'}">${res.verified ? 'SIGNATURE VALID' : 'SIGNATURE INVALID'}</span> ${escapeHtml(res.reason || res.error || '')}`;
});

async function loadTokenMutations() {
  const data = await api('/api/mutations/token-list');
  state.tokenMutations = data.mutations || [];
  renderTokenFuzzerTable();
}

function renderTokenFuzzerTable() {
  const wrap = $('tokenFuzzerList');
  const summaryEl = $('tokenFuzzerSummary');
  if (!state.tokenMutations.length) {
    wrap.innerHTML = '<div class="muted">No token probes loaded.</div>';
    return;
  }
  if (state.tokenBatchResults.size > 0) {
    const all = [...state.tokenBatchResults.values()];
    const acc = all.filter((r) => r.accepted).length;
    summaryEl.innerHTML = `${all.length} probed · <span style="color:${acc ? '#f87171' : '#4ade80'}">${acc} ACCEPTED (RISK)</span> · ${all.length - acc} blocked`;
  }
  wrap.innerHTML = `
    <table class="mut-table">
      <thead><tr><th>Probe</th><th>Result</th></tr></thead>
      <tbody>
        ${state.tokenMutations
          .map((m) => {
            const res = state.tokenBatchResults.get(m.id);
            const cell = res
              ? `<span class="badge ${res.accepted ? 'badge-danger' : 'badge-ok'}">${escapeHtml(res.verdict)} (${res.status})</span>`
              : '<span class="muted">-</span>';
            return `<tr><td><div style="font-weight:600;">${escapeHtml(m.label)}</div><div class="muted">${escapeHtml(m.description)}</div></td><td>${cell}</td></tr>`;
          })
          .join('')}
      </tbody>
    </table>
  `;
}

$('batchTokenBtn').addEventListener('click', async () => {
  const url = $('repUrl').value.trim();
  if (!url) return;
  let headers = {};
  try { headers = JSON.parse($('repHeaders').value || '{}'); } catch { headers = {}; }
  const data = await api('/api/mutations/token/batch', {
    method: 'POST',
    body: JSON.stringify({
      url,
      headers,
      body: $('repBody').value,
      attackerHost: $('attackerHostInput').value.trim() || 'attacker.example',
      useCookieJar: $('repUseCookieJar').checked,
    }),
  });
  state.tokenBatchResults.clear();
  for (const r of data.results || []) {
    state.tokenBatchResults.set(r.id, r);
  }
  renderTokenFuzzerTable();
  await loadTraces();
});

function toBase64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function randomToken(len = 32) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

function showCopyFeedback(msg) {
  $('copyFeedback').textContent = msg;
  setTimeout(() => {
    if ($('copyFeedback').textContent === msg) $('copyFeedback').textContent = '';
  }, 2000);
}

async function copyToClipboard(text, label) {
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

async function copyTraceAsCurl(trace) {
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

$('copyCurlBtn').addEventListener('click', async () => {
  const trace = state.traces.find((t) => t.id === state.selectedTraceId);
  if (trace) await copyTraceAsCurl(trace);
});

$('copyRawHttpBtn').addEventListener('click', async () => {
  const trace = state.traces.find((t) => t.id === state.selectedTraceId);
  if (!trace) return;
  let pathPart = trace.request.url;
  let hostPart = '';
  try {
    const u = new URL(trace.request.url);
    pathPart = `${u.pathname}${u.search}`;
    hostPart = u.host;
  } catch {
    // Fallback to raw URL
  }
  const lines = [`${trace.request.method} ${pathPart} HTTP/1.1`];
  if (hostPart) lines.push(`Host: ${hostPart}`);
  for (const [k, v] of Object.entries(trace.request.headers || {})) {
    lines.push(`${k}: ${v}`);
  }
  lines.push('', trace.request.body || '');
  await copyToClipboard(lines.join('\r\n'), 'Copied Raw HTTP');
});

$('copyMdReportBtn').addEventListener('click', async () => {
  const trace = state.traces.find((t) => t.id === state.selectedTraceId);
  if (!trace) return;
  const findings = (trace.audit?.findings || [])
    .map((f) => `- **[${f.severity}]** ${f.title}: ${f.detail}`)
    .join('\n');
  const md = [
    `### OAuth Trace Finding — ${trace.request.method} ${trace.request.url}`,
    `- **Timestamp:** ${trace.timestamp}`,
    `- **Response:** HTTP ${trace.response.status}${trace.response.location ? ` -> \`${trace.response.location}\`` : ''}`,
    '',
    '#### Audit Findings',
    findings || '- No findings flagged.',
    '',
    '#### Request',
    '```http',
    `${trace.request.method} ${trace.request.url}`,
    ...Object.entries(trace.request.headers || {}).map(([k, v]) => `${k}: ${v}`),
    '',
    trace.request.body || '',
    '```',
  ].join('\n');
  await copyToClipboard(md, 'Copied Markdown Report');
});

$('setBaselineBtn').addEventListener('click', () => {
  if (!state.selectedTraceId) return;
  state.baselineTraceId = state.selectedTraceId;
  renderSelectedTrace();
});

$('clearBaselineBtn').addEventListener('click', () => {
  state.baselineTraceId = null;
  renderSelectedTrace();
});

$('genPkceBtn').addEventListener('click', async () => {
  const verifier = randomToken(32);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = toBase64Url(new Uint8Array(digest));
  try {
    const u = new URL($('repUrl').value);
    u.searchParams.set('code_challenge', challenge);
    u.searchParams.set('code_challenge_method', 'S256');
    $('repUrl').value = u.toString();
  } catch {
    // Ignore if URL not valid yet
  }
  $('pkceVerifierBox').style.display = 'block';
  $('pkceVerifierBox').textContent = `code_verifier: ${verifier}`;
});

$('genStateBtn').addEventListener('click', () => {
  try {
    const u = new URL($('repUrl').value);
    u.searchParams.set('state', randomToken(16));
    u.searchParams.set('nonce', randomToken(16));
    $('repUrl').value = u.toString();
  } catch {
    // Ignore
  }
});

function connectTraceStream() {
  const es = new EventSource('/api/traces/stream');
  es.addEventListener('connected', () => {
    $('sseStatus').textContent = 'SSE: live';
    $('sseStatus').className = 'badge badge-ok';
  });
  es.addEventListener('trace', (ev) => {
    try {
      const entry = JSON.parse(ev.data);
      if (!state.traces.some((t) => t.id === entry.id)) {
        state.traces.unshift(entry);
        if (!state.selectedTraceId) state.selectedTraceId = entry.id;
        renderTraceList();
        renderSequenceDiagram();
      }
    } catch {
      // Ignore parse errors
    }
  });
  es.addEventListener('clear', () => {
    state.traces = [];
    state.selectedTraceId = null;
    renderTraceList();
    renderSequenceDiagram();
  });
  es.onerror = () => {
    $('sseStatus').textContent = 'SSE: reconnecting';
    $('sseStatus').className = 'badge badge-warn';
  };
}

function initResizers() {
  const layout = document.querySelector('.layout');
  const savedSidebar = localStorage.getItem('owb_sidebar_w');
  if (savedSidebar) layout.style.setProperty('--sidebar-w', `${savedSidebar}px`);

  const savedDiagram = localStorage.getItem('owb_diagram_h');
  if (savedDiagram) document.documentElement.style.setProperty('--diagram-h', `${savedDiagram}px`);

  function attachDrag(handle, onMove) {
    if (!handle) return;
    handle.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      handle.classList.add('dragging');
      document.body.style.userSelect = 'none';

      const moveHandler = (ev) => onMove(ev);
      const upHandler = () => {
        handle.classList.remove('dragging');
        document.body.style.userSelect = '';
        window.removeEventListener('pointermove', moveHandler);
        window.removeEventListener('pointerup', upHandler);
      };

      window.addEventListener('pointermove', moveHandler);
      window.addEventListener('pointerup', upHandler);
    });
  }

  attachDrag($('sidebarResizer'), (ev) => {
    const w = Math.max(220, Math.min(560, ev.clientX));
    layout.style.setProperty('--sidebar-w', `${w}px`);
    localStorage.setItem('owb_sidebar_w', String(Math.round(w)));
  });

  const diagramCanvas = $('sequenceDiagram');
  attachDrag($('diagramResizer'), (ev) => {
    const rect = diagramCanvas.getBoundingClientRect();
    const h = Math.max(90, Math.min(460, ev.clientY - rect.top));
    document.documentElement.style.setProperty('--diagram-h', `${h}px`);
    localStorage.setItem('owb_diagram_h', String(Math.round(h)));
  });

  document.querySelectorAll('.split-resizer').forEach((resizer) => {
    const split = resizer.closest('.split-2');
    attachDrag(resizer, (ev) => {
      const rect = split.getBoundingClientRect();
      const pct = Math.max(20, Math.min(80, ((ev.clientX - rect.left) / rect.width) * 100));
      split.style.setProperty('--split-left', `${pct.toFixed(1)}%`);
      split.style.setProperty('--split-right', `${(100 - pct).toFixed(1)}%`);
    });
  });
}

// Help Modal
function toggleHelp(show) {
  $('helpModal').style.display = show ? 'flex' : 'none';
}
$('helpBtn').addEventListener('click', () => toggleHelp(true));
$('closeHelpBtn').addEventListener('click', () => toggleHelp(false));
$('helpModal').addEventListener('click', (e) => {
  if (e.target === $('helpModal')) toggleHelp(false);
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') toggleHelp(false);
  if (e.key === '?' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
    toggleHelp($('helpModal').style.display === 'none');
  }
});

// Floating viewport-clamped tooltips (never clipped by overflow:auto panes)
function initTooltips() {
  const tipEl = document.createElement('div');
  tipEl.className = 'floating-tooltip';
  document.body.appendChild(tipEl);

  let activeTarget = null;

  document.addEventListener('mouseover', (e) => {
    const target = e.target.closest?.('[data-tip]');
    if (!target) return;
    activeTarget = target;
    tipEl.textContent = target.dataset.tip;
    tipEl.style.display = 'block';

    const rect = target.getBoundingClientRect();
    const tipRect = tipEl.getBoundingClientRect();
    let left = rect.left + rect.width / 2 - tipRect.width / 2;
    left = Math.max(8, Math.min(window.innerWidth - tipRect.width - 8, left));

    let top = rect.bottom + 6;
    if (top + tipRect.height > window.innerHeight - 8) {
      top = Math.max(8, rect.top - tipRect.height - 6);
    }

    tipEl.style.left = `${Math.round(left)}px`;
    tipEl.style.top = `${Math.round(top)}px`;
  });

  document.addEventListener('mouseout', (e) => {
    if (!activeTarget) return;
    const related = e.relatedTarget;
    if (!related || !activeTarget.contains(related)) {
      activeTarget = null;
      tipEl.style.display = 'none';
    }
  });
}

// Init
initTooltips();
initResizers();
loadMockConfig();
loadParamMutations();
loadTokenMutations();
loadCustomPresets();
refreshCustomParamOptions();
refreshRedirectMutations('http://localhost:3000/callback');
refreshCookieJarBadge();
loadTraces();
connectTraceStream();
