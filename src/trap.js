import crypto from 'node:crypto';
import express from 'express';
import { parseOAuthUrl } from './oauth/parser.js';
import { auditOAuthContext } from './oauth/analyzer.js';

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildFullUrl(req) {
  const host = req.get('host') || req.hostname || 'unknown.local';
  return `${req.protocol}://${host}${req.originalUrl}`;
}

function formatCapturedBody(body) {
  if (!body) return { bodyStr: '', bodyParams: {} };
  if (typeof body === 'string') return { bodyStr: body, bodyParams: {} };
  if (typeof body === 'object' && !Array.isArray(body)) {
    return {
      bodyStr: JSON.stringify(body, null, 2),
      bodyParams: body,
    };
  }
  return { bodyStr: String(body), bodyParams: {} };
}

function renderCaptureHtml(title, subtitleHtml) {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head>
<body style="font-family: ui-monospace, monospace; background:#0b1120; color:#f1f5f9; padding:24px;">
  <h2>${escapeHtml(title)}</h2>
  <p>${subtitleHtml}</p>
  <pre id="out"></pre>
  <script>
    document.getElementById('out').textContent = window.location.href;
    if (window.location.hash && window.location.hash.length > 1) {
      fetch('/api/callback-fragment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fullUrl: window.location.href })
      });
    }
  </script>
</body>
</html>`;
}

/**
 * Registers the host-based catch-all attacker trap middleware and /callback listeners.
 * @param {express.Express} app
 * @param {import('./tracer.js').TraceStore} store
 */
export function registerTrapAndCallback(app, store) {
  app.use(express.urlencoded({ extended: false }));

  // Host-based Catch-All Trap: captures any path when accessed via non-local Host (e.g. /etc/hosts attacker.example -> 127.0.0.1)
  app.use((req, res, next) => {
    const reqHost = (req.hostname || '').toLowerCase();
    const isLocal = reqHost === 'localhost' || reqHost === '127.0.0.1' || reqHost === '::1';
    if (isLocal || req.path === '/api/callback-fragment') {
      return next();
    }

    const fullUrl = buildFullUrl(req);
    let parsed;
    try {
      parsed = parseOAuthUrl(fullUrl);
    } catch {
      parsed = { oauthParams: {}, flowKind: 'attacker_trap' };
    }

    const { bodyStr, bodyParams } = formatCapturedBody(req.body);
    const mergedParams = { ...parsed.oauthParams, ...bodyParams };
    const audit = auditOAuthContext({
      requestHeaders: req.headers,
      oauthParams: mergedParams,
      status: 200,
    });

    store.add({
      id: crypto.randomUUID(),
      traceGroupId: crypto.randomUUID(),
      hopIndex: 0,
      timestamp: new Date().toISOString(),
      label: 'attacker_trap',
      flowKind: `trap:${req.method}:${parsed.flowKind || 'hit'}`,
      durationMs: 0,
      request: {
        method: req.method,
        url: fullUrl,
        headers: req.headers,
        body: bodyStr,
        oauthParams: mergedParams,
      },
      response: {
        status: 200,
        statusText: 'Trap Captured',
        headers: { 'content-type': 'text/html' },
        cookies: [],
        location: null,
        body: '',
        oauthParams: mergedParams,
      },
      audit,
    });

    const hostLabel = escapeHtml(req.get('host') || reqHost);
    const pathLabel = escapeHtml(req.originalUrl);
    return res.type('html').send(
      renderCaptureHtml(
        'Attacker Trap Captured',
        `Host: <strong>${hostLabel}</strong> · Path: <strong>${pathLabel}</strong>`
      )
    );
  });

  // Local OAuth callback listener (POST form_post)
  app.post('/callback', (req, res) => {
    const fullUrl = buildFullUrl(req);
    const { bodyStr, bodyParams } = formatCapturedBody(req.body);
    let parsed;
    try {
      parsed = parseOAuthUrl(fullUrl);
    } catch {
      parsed = { oauthParams: {} };
    }
    const mergedParams = { ...parsed.oauthParams, ...bodyParams };
    const audit = auditOAuthContext({ oauthParams: mergedParams, status: 200 });

    store.add({
      id: crypto.randomUUID(),
      traceGroupId: crypto.randomUUID(),
      hopIndex: 0,
      timestamp: new Date().toISOString(),
      label: 'local_callback_form_post',
      flowKind: bodyParams.id_token || bodyParams.access_token ? 'form_post_token_callback' : 'form_post_callback',
      durationMs: 0,
      request: {
        method: 'POST',
        url: fullUrl,
        headers: req.headers,
        body: bodyStr,
        oauthParams: mergedParams,
      },
      response: {
        status: 200,
        statusText: 'OK',
        headers: { 'content-type': 'text/html' },
        cookies: [],
        location: null,
        body: '',
        oauthParams: mergedParams,
      },
      audit,
    });

    return res.type('html').send(renderCaptureHtml('OAuth form_post Callback Captured', 'Logged to OAuth Workbench.'));
  });

  // Local OAuth callback listener (GET query + #fragment)
  app.get('/callback', (req, res) => {
    const fullUrl = buildFullUrl(req);
    const parsed = parseOAuthUrl(fullUrl);
    const audit = auditOAuthContext({ oauthParams: parsed.oauthParams, status: 200 });

    store.add({
      id: crypto.randomUUID(),
      traceGroupId: crypto.randomUUID(),
      hopIndex: 0,
      timestamp: new Date().toISOString(),
      label: 'local_callback_listener',
      flowKind: parsed.flowKind,
      durationMs: 0,
      request: {
        method: 'GET',
        url: fullUrl,
        headers: req.headers,
        body: '',
        oauthParams: parsed.oauthParams,
      },
      response: {
        status: 200,
        statusText: 'OK',
        headers: { 'content-type': 'text/html' },
        cookies: [],
        location: null,
        body: '',
        oauthParams: parsed.oauthParams,
      },
      audit,
    });

    return res.type('html').send(
      renderCaptureHtml('OAuth Callback Captured', 'Query parameters were logged to OAuth Workbench.')
    );
  });

  app.post('/api/callback-fragment', (req, res) => {
    const { fullUrl } = req.body || {};
    if (!fullUrl) return res.status(400).json({ error: 'Missing fullUrl' });
    try {
      const parsed = parseOAuthUrl(fullUrl);
      const audit = auditOAuthContext({ oauthParams: parsed.oauthParams, status: 200 });
      store.add({
        id: crypto.randomUUID(),
        traceGroupId: crypto.randomUUID(),
        hopIndex: 0,
        timestamp: new Date().toISOString(),
        label: 'local_callback_fragment',
        flowKind: parsed.flowKind,
        durationMs: 0,
        request: {
          method: 'GET',
          url: fullUrl,
          headers: {},
          body: '',
          oauthParams: parsed.oauthParams,
        },
        response: {
          status: 200,
          statusText: 'Fragment Captured',
          headers: {},
          cookies: [],
          location: null,
          body: '',
          oauthParams: parsed.oauthParams,
        },
        audit,
      });
      return res.json({ captured: true, oauthParams: parsed.oauthParams });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  });
}
