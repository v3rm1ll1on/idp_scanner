const state = {
  traces: [],
  selectedTraceId: null,
  baselineTraceId: null,
  redirectMutations: [],
  batchResults: new Map(),
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
      const findingsCount = (t.audit?.findings || []).filter((f) => f.severity === 'HIGH' || f.severity === 'MEDIUM').length;
      const urlObj = (() => {
        try { return new URL(t.request.url); } catch { return { pathname: t.request.url }; }
      })();
      return `
        <div class="trace-item ${active}" data-id="${t.id}">
          <div class="trace-row">
            <span>
              <span class="badge badge-muted">${escapeHtml(t.request.method)}</span>
              <span class="badge ${statusBadgeClass(t.response.status)}">${t.response.status || 'ERR'}</span>
            </span>
            <span class="muted mono">${t.durationMs}ms${findingsCount ? ` · <span style="color:#fbbf24">${findingsCount}f</span>` : ''}</span>
          </div>
          <div class="trace-url" title="${escapeHtml(t.request.url)}">${escapeHtml(urlObj.pathname + (urlObj.search || ''))}</div>
          <div class="muted" style="font-size:11px;">${escapeHtml(t.flowKind || t.label)}</div>
        </div>
      `;
    })
    .join('');

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
  if (!audit) {
    findingsEl.textContent = 'No audit data.';
    jwtEl.innerHTML = '';
    return;
  }

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
  if (state.redirectMutations.length === 0) {
    wrap.innerHTML = '<div class="muted">Click Generate to build redirect_uri payloads.</div>';
    return;
  }

  const rows = state.redirectMutations
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
  const container = $('paramMutationBtns');
  container.innerHTML = (res.paramMutations || [])
    .map((m) => `<button class="chip" data-patch='${escapeHtml(JSON.stringify(m.patch))}' title="${escapeHtml(m.description)}">${escapeHtml(m.label)}</button>`)
    .join('');

  container.querySelectorAll('.chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      try {
        const u = new URL($('repUrl').value);
        const patch = JSON.parse(chip.dataset.patch);
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
    });
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
  $('discoveryOutput').textContent = JSON.stringify(data, null, 2);
  await loadTraces();
});

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
  }
  await refreshCookieJarBadge();
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

$('copyCurlBtn').addEventListener('click', async () => {
  const trace = state.traces.find((t) => t.id === state.selectedTraceId);
  if (!trace) return;
  const parts = [`curl -i -X ${trace.request.method}`];
  for (const [k, v] of Object.entries(trace.request.headers || {})) {
    parts.push(`-H ${JSON.stringify(`${k}: ${v}`)}`);
  }
  if (trace.request.body) {
    parts.push(`--data-raw ${JSON.stringify(trace.request.body)}`);
  }
  parts.push(JSON.stringify(trace.request.url));
  await navigator.clipboard.writeText(parts.join(' \\\n  '));
  showCopyFeedback('Copied cURL');
});

$('copyRawHttpBtn').addEventListener('click', async () => {
  const trace = state.traces.find((t) => t.id === state.selectedTraceId);
  if (!trace) return;
  const u = new URL(trace.request.url);
  const lines = [`${trace.request.method} ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`];
  for (const [k, v] of Object.entries(trace.request.headers || {})) {
    lines.push(`${k}: ${v}`);
  }
  lines.push('', trace.request.body || '');
  await navigator.clipboard.writeText(lines.join('\r\n'));
  showCopyFeedback('Copied Raw HTTP');
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
refreshRedirectMutations('http://localhost:3000/callback');
refreshCookieJarBadge();
loadTraces();
connectTraceStream();
