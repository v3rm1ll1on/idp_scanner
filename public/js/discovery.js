import { $, escapeHtml, copyToClipboard, randomToken } from './state.js';

export function renderDiscovery(data, { onRefreshRedirectMutations, onRefreshCustomParams }) {
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
        actionBtn = `<button class="btn btn-primary disc-load-auth" data-url="${escapeHtml(url)}" data-tip="Build a starter Authorization request and load it into Repeater.">Build Auth -&gt; Repeater</button>`;
      } else if (kind === 'token') {
        actionBtn = `<button class="btn btn-secondary disc-load-token" data-url="${escapeHtml(url)}" data-tip="Load a POST /token template into Repeater.">Load POST -&gt; Repeater</button>`;
      } else if (kind === 'userinfo' || kind === 'jwks') {
        actionBtn = `<button class="btn btn-secondary disc-load-get" data-url="${escapeHtml(url)}" data-tip="Load GET request into Repeater.">Load GET -&gt; Repeater</button>`;
      }
      return `
        <tr>
          <td>${escapeHtml(label)}</td>
          <td class="mono">${escapeHtml(url)}</td>
          <td>
            <div class="disc-actions">
              <button class="btn btn-ghost disc-copy-url" data-url="${escapeHtml(url)}" data-tip="Copy endpoint URL.">Copy</button>
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
        <div>${scopes.map((sc) => `<span class="badge badge-muted disc-copy-scope" data-scope="${escapeHtml(sc)}" style="margin:2px;cursor:pointer;" data-tip="Click to copy scope">${escapeHtml(sc)}</span>`).join('') || '<span class="muted">not listed</span>'}</div>
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
      onRefreshRedirectMutations(`${window.location.origin}/callback`);
      onRefreshCustomParams();
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
      onRefreshCustomParams();
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
      onRefreshCustomParams();
      document.querySelector('[data-tab="repeater"]').click();
    });
  });
}
