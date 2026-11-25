const state = {
  traces: [],
  selectedTraceId: null,
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

function renderSelectedTrace() {
  const trace = state.traces.find((t) => t.id === state.selectedTraceId);
  if (!trace) return;

  $('reqSummary').textContent = `${trace.request.method} ${trace.request.url}`;
  $('reqOAuthParams').textContent = JSON.stringify(trace.request.oauthParams || {}, null, 2);
  $('reqHeaders').textContent = JSON.stringify(trace.request.headers || {}, null, 2);
  $('reqBody').textContent = trace.request.body || '(empty)';

  $('resStatusBadge').innerHTML = `<span class="badge ${statusBadgeClass(trace.response.status)}">${trace.response.status} ${escapeHtml(trace.response.statusText || '')}</span>`;
  $('resSummary').textContent = trace.response.location
    ? `HTTP ${trace.response.status} -> Location: ${trace.response.location}`
    : `HTTP ${trace.response.status} (${trace.durationMs}ms)`;
  $('resOAuthParams').textContent = JSON.stringify(trace.response.oauthParams || {}, null, 2);
  $('resHeaders').textContent = JSON.stringify(trace.response.headers || {}, null, 2);
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

  let svg = `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">`;
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
      const statusCell = res
        ? `<span class="badge ${res.accepted ? 'badge-danger' : 'badge-ok'}">${res.accepted ? `ACCEPTED (${res.status})` : `BLOCKED (${res.status})`}</span>`
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
      label: 'repeater',
    }),
  });
  if (data.hops && data.hops.length > 0) {
    state.selectedTraceId = data.hops[0].id;
  }
  await loadTraces();
});

$('refreshMutationsBtn').addEventListener('click', () => refreshRedirectMutations());

$('batchRedirectBtn').addEventListener('click', async () => {
  const baseUrl = $('repUrl').value.trim();
  if (!baseUrl) return;
  const attackerHost = $('attackerHostInput').value.trim() || 'attacker.example';
  const data = await api('/api/mutations/redirect-uri/batch', {
    method: 'POST',
    body: JSON.stringify({ baseUrl, attackerHost }),
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

// Init
loadMockConfig();
loadParamMutations();
refreshRedirectMutations('http://localhost:3000/callback');
loadTraces();
