import { state, $, api, escapeHtml } from './state.js';

export function extractRedirectFromRepeater() {
  try {
    return new URL($('repUrl').value).searchParams.get('redirect_uri');
  } catch {
    return null;
  }
}

export async function refreshRedirectMutations(baseRedirectUri) {
  const attackerHost = $('attackerHostInput').value.trim() || 'attacker.example';
  const uri = baseRedirectUri || extractRedirectFromRepeater() || 'http://localhost:3000/callback';
  const data = await api('/api/mutations/redirect-uri', {
    method: 'POST',
    body: JSON.stringify({ baseRedirectUri: uri, attackerHost }),
  });
  state.redirectMutations = data.mutations || [];
  renderRedirectMutations();
}

export function renderRedirectMutations() {
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
          <td><button class="btn btn-secondary use-mut-btn" data-uri="${escapeHtml(m.uri)}" data-tip="Load this redirect_uri payload into Repeater.">Load</button></td>
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

export function applyParamPatchToRepeater(patch) {
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

export function mutateTokenBody(mutator) {
  const params = new URLSearchParams($('repBody').value || '');
  mutator(params);
  $('repBody').value = params.toString();
}

export function setBodyField(name, payload) {
  const raw = ($('repBody').value || '').trim();
  if (raw.startsWith('{')) {
    try {
      const obj = JSON.parse(raw);
      if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
        obj[name] = payload;
        $('repBody').value = JSON.stringify(obj, null, 2);
        return;
      }
    } catch {
      // Fallback to form-urlencoded below
    }
  }
  mutateTokenBody((p) => p.set(name, payload));
}

export async function loadParamMutations() {
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

export function renderParamFuzzerTable() {
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
          <td><button class="btn btn-secondary use-param-mut-btn" data-patch='${escapeHtml(JSON.stringify(m.patch))}' data-tip="Apply this mutation to Repeater URL.">Load</button></td>
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

export async function loadTokenMutations() {
  const data = await api('/api/mutations/token-list');
  state.tokenMutations = data.mutations || [];
  renderTokenFuzzerTable();
}

export function renderTokenFuzzerTable() {
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
  } else {
    summaryEl.textContent = 'Load a POST /token request into Repeater.';
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

export function refreshCustomParamOptions() {
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

export async function loadCustomPresets() {
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

export function renderCustomFuzzerTable() {
  const wrap = $('customFuzzerList');
  const summaryEl = $('customFuzzerSummary');
  const data = state.customBatchData;
  if (!data || !data.results) {
    summaryEl.textContent = 'Select a parameter and payloads.';
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
            <td><button class="btn btn-secondary use-custom-payload-btn" data-payload="${escapeHtml(r.payload)}" data-tip="Load this payload into Repeater.">Load</button></td>
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
        setBodyField(name, payload);
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
