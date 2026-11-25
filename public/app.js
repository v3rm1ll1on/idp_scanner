import {
  state,
  $,
  api,
  withBusyButton,
  escapeHtml,
  statusBadgeClass,
  toBase64Url,
  randomToken,
  copyToClipboard,
} from './js/state.js';
import { initTooltips, initResizers, initTabsAndHelp } from './js/ui-layout.js';
import { renderDiscovery } from './js/discovery.js';
import {
  refreshRedirectMutations,
  renderRedirectMutations,
  applyParamPatchToRepeater,
  mutateTokenBody,
  loadParamMutations,
  renderParamFuzzerTable,
  loadTokenMutations,
  renderTokenFuzzerTable,
  refreshCustomParamOptions,
  loadCustomPresets,
  renderCustomFuzzerTable,
} from './js/fuzzers.js';
import {
  loadTraces,
  refreshCookieJarBadge,
  copyTraceAsCurl,
  renderTraceList,
  renderSelectedTrace,
  renderAudit,
  renderJwtCard,
  renderSequenceDiagram,
} from './js/inspector.js';

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
    state.baselineTraceId = null;
    state.expandedTraces.clear();
    renderTraceList();
    renderSelectedTrace();
    renderSequenceDiagram();
  });
  es.onerror = () => {
    $('sseStatus').textContent = 'SSE: reconnecting';
    $('sseStatus').className = 'badge badge-warn';
  };
}

// Topbar & Parser events
$('discoverBtn').addEventListener('click', async () => {
  const issuerUrl = $('issuerInput').value.trim();
  if (!issuerUrl) return;
  const data = await api('/api/discover', { method: 'POST', body: JSON.stringify({ issuerUrl }) });
  renderDiscovery(data, {
    onRefreshRedirectMutations: refreshRedirectMutations,
    onRefreshCustomParams: refreshCustomParamOptions,
  });
  document.querySelector('[data-tab="discovery"]').click();
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
  state.baselineTraceId = null;
  state.expandedTraces.clear();
  state.batchResults.clear();
  state.paramBatchResults.clear();
  state.tokenBatchResults.clear();
  state.customBatchData = null;
  $('repResponsePreview').textContent = 'Send a request to preview the response here.';
  $('repResTabBadge').textContent = '-';
  $('repResTabBadge').className = 'badge badge-muted';
  renderRedirectMutations();
  renderParamFuzzerTable();
  renderTokenFuzzerTable();
  renderCustomFuzzerTable();
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

// Repeater & Fuzzer events
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
  } else if (data.error) {
    $('repResponsePreview').textContent = `Error: ${data.error}`;
    document.querySelector('.rep-subtab[data-reptab="response"]').click();
  }
  await refreshCookieJarBadge();
  await loadTraces();
});

$('repOpenBrowserBtn').addEventListener('click', () => {
  const url = $('repUrl').value.trim();
  if (url) window.open(url, '_blank', 'noopener');
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

$('clearCookiesBtn').addEventListener('click', async () => {
  await api('/api/cookies', { method: 'DELETE' });
  await refreshCookieJarBadge();
});

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
    // Ignore
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

$('refreshMutationsBtn').addEventListener('click', () => refreshRedirectMutations());
$('redirectOnlyAccepted').addEventListener('change', renderRedirectMutations);
$('paramOnlyAccepted').addEventListener('change', renderParamFuzzerTable);
$('customOnlyAnomalies').addEventListener('change', renderCustomFuzzerTable);
$('repUrl').addEventListener('change', refreshCustomParamOptions);
$('repBody').addEventListener('change', refreshCustomParamOptions);

$('batchRedirectBtn').addEventListener('click', async () => {
  const baseUrl = $('repUrl').value.trim();
  if (!baseUrl) return;
  const attackerHost = $('attackerHostInput').value.trim() || 'attacker.example';
  const useCookieJar = $('repUseCookieJar').checked;
  await withBusyButton($('batchRedirectBtn'), 'Probing...', async () => {
    const data = await api('/api/mutations/redirect-uri/batch', {
      method: 'POST',
      body: JSON.stringify({ baseUrl, attackerHost, useCookieJar }),
    });
    if (data.error) {
      $('redirectFuzzerSummary').innerHTML = `<span class="badge badge-danger">${escapeHtml(data.error)}</span>`;
      return;
    }
    state.batchResults.clear();
    for (const r of data.results || []) state.batchResults.set(r.id, r);
    renderRedirectMutations();
    await loadTraces();
  });
});

$('batchParamsBtn').addEventListener('click', async () => {
  const baseUrl = $('repUrl').value.trim();
  if (!baseUrl) return;
  const useCookieJar = $('repUseCookieJar').checked;
  await withBusyButton($('batchParamsBtn'), 'Running...', async () => {
    const data = await api('/api/mutations/params/batch', {
      method: 'POST',
      body: JSON.stringify({ baseUrl, useCookieJar }),
    });
    if (data.error) {
      $('paramFuzzerSummary').innerHTML = `<span class="badge badge-danger">${escapeHtml(data.error)}</span>`;
      return;
    }
    state.paramBatchResults.clear();
    for (const r of data.results || []) state.paramBatchResults.set(r.id, r);
    renderParamFuzzerTable();
    await loadTraces();
  });
});

$('batchTokenBtn').addEventListener('click', async () => {
  const url = $('repUrl').value.trim();
  if (!url) return;
  let headers = {};
  try { headers = JSON.parse($('repHeaders').value || '{}'); } catch { headers = {}; }
  await withBusyButton($('batchTokenBtn'), 'Probing...', async () => {
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
    if (data.error) {
      $('tokenFuzzerSummary').innerHTML = `<span class="badge badge-danger">${escapeHtml(data.error)}</span>`;
      return;
    }
    state.tokenBatchResults.clear();
    for (const r of data.results || []) state.tokenBatchResults.set(r.id, r);
    renderTokenFuzzerTable();
    await loadTraces();
  });
});

$('customParamSelect').addEventListener('change', (e) => {
  const val = e.target.value;
  if (!val) return;
  const idx = val.indexOf(':');
  $('customTargetLoc').value = val.slice(0, idx);
  $('customParamInput').value = val.slice(idx + 1);
});

$('customPresetSelect').addEventListener('change', (e) => {
  const preset = state.customPresets.find((p) => p.id === e.target.value);
  if (preset) $('customPayloadsInput').value = preset.payloads.join('\n');
  e.target.value = '';
});

$('batchCustomBtn').addEventListener('click', async () => {
  const baseUrl = $('repUrl').value.trim();
  const paramName = $('customParamInput').value.trim();
  const targetLocation = $('customTargetLoc').value;
  const payloads = $('customPayloadsInput').value.split('\n').map((s) => s.replace(/\r$/, ''));
  if (!baseUrl || !paramName || payloads.length === 0) return;

  let headers = {};
  try { headers = JSON.parse($('repHeaders').value || '{}'); } catch { headers = {}; }

  await withBusyButton($('batchCustomBtn'), 'Fuzzing...', async () => {
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
    if (data.error) {
      $('customFuzzerSummary').innerHTML = `<span class="badge badge-danger">${escapeHtml(data.error)}</span>`;
      return;
    }
    state.customBatchData = data;
    renderCustomFuzzerTable();
    await loadTraces();
  });
});

// Inspector & JWT events
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
    // Fallback
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

// Init
const isDemoMode = new URLSearchParams(window.location.search).get('demo') === 'true';
if (isDemoMode) {
  $('demoFlowBtn').style.display = 'inline-block';
  $('mockConfigSection').style.display = 'block';
  if (!$('issuerInput').value) {
    $('issuerInput').value = `${window.location.origin}/mock-idp`;
  }
  loadMockConfig();
}

initTooltips();
initResizers();
initTabsAndHelp();
loadParamMutations();
loadTokenMutations();
loadCustomPresets();
refreshCustomParamOptions();
refreshRedirectMutations('http://localhost:3000/callback');
refreshCookieJarBadge();
loadTraces();
connectTraceStream();
