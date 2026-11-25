import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { createMockIdp } from './mock-idp.js';
import { TraceStore, sendAndTrace, batchTestRedirectUris, batchTestOAuthParams, batchTestCustomField, batchTestTokenEndpoint } from './tracer.js';
import { parseOAuthUrl, parseRawHttpRequest, summarizeDiscovery } from './oauth/parser.js';
import { auditOAuthContext } from './oauth/analyzer.js';
import { generateRedirectUriMutations, getOAuthParameterMutations, getCustomFieldPresets, getTokenEndpointMutations } from './oauth/payloads.js';
import { inspectJwt, verifyJwtWithJwks } from './oauth/jwt.js';
import { CookieJar } from './oauth/cookies.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Builds the Express application for OAuth Workbench.
 * @returns {{app: express.Express, store: TraceStore, mockIdp: object, cookieJar: CookieJar}}
 */
export function createApp() {
  const app = express();
  const store = new TraceStore();
  const mockIdp = createMockIdp();
  const cookieJar = new CookieJar();

  app.use(express.json({ limit: '2mb' }));
  app.use('/mock-idp', mockIdp.router);
  app.use(express.static(path.join(__dirname, '..', 'public')));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, version: '0.1.0' });
  });

  app.get('/api/traces', (_req, res) => {
    res.json({ traces: store.list() });
  });

  app.get('/api/traces/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const sendEvent = (event, data) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    sendEvent('connected', { ok: true });
    const unsubscribe = store.subscribe((event, payload) => {
      sendEvent(event, payload);
    });

    req.on('close', () => {
      unsubscribe();
    });
  });

  app.delete('/api/traces', (_req, res) => {
    store.clear();
    res.json({ cleared: true });
  });

  app.post('/api/parse', (req, res) => {
    const { input } = req.body || {};
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Missing input string' });
    }

    try {
      const trimmed = input.trim();
      const isUrl = /^https?:\/\//i.test(trimmed);
      const parsed = isUrl
        ? { method: 'GET', headers: {}, body: '', ...parseOAuthUrl(trimmed) }
        : parseRawHttpRequest(trimmed);

      const audit = auditOAuthContext({ oauthParams: parsed.oauthParams });
      const baseRedirect = parsed.oauthParams.redirect_uri || 'http://localhost:3000/callback';
      const redirectMutations = generateRedirectUriMutations(baseRedirect);
      const paramMutations = getOAuthParameterMutations();

      return res.json({
        parsed,
        audit,
        redirectMutations,
        paramMutations,
      });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  });

  app.post('/api/discover', async (req, res) => {
    const { issuerUrl, headers = {} } = req.body || {};
    if (!issuerUrl || typeof issuerUrl !== 'string') {
      return res.status(400).json({ error: 'Missing issuerUrl' });
    }

    let normalized = issuerUrl.trim().replace(/\/+$/, '');
    if (!/^https?:\/\//i.test(normalized)) {
      const isLocal = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i.test(normalized);
      normalized = `${isLocal ? 'http' : 'https'}://${normalized}`;
    }
    const base = normalized;
    const candidates = base.includes('/.well-known/')
      ? [base]
      : [`${base}/.well-known/openid-configuration`, `${base}/.well-known/oauth-authorization-server`];

    for (const candidate of candidates) {
      try {
        const hops = await sendAndTrace(store, {
          method: 'GET',
          url: candidate,
          headers: { Accept: 'application/json', ...headers },
          followRedirects: true,
          label: 'oidc_discovery',
        });
        const last = hops[hops.length - 1];
        if (last && last.response.status === 200) {
          const doc = JSON.parse(last.response.body);
          return res.json({
            endpoint: candidate,
            summary: summarizeDiscovery(doc),
            raw: doc,
            traces: hops,
          });
        }
      } catch {
        // Try next discovery candidate
      }
    }

    return res.status(404).json({ error: 'No OIDC/OAuth2 discovery document found at well-known endpoints' });
  });

  app.get('/api/cookies', (_req, res) => {
    res.json({ cookies: cookieJar.list() });
  });

  app.delete('/api/cookies', (_req, res) => {
    cookieJar.clear();
    res.json({ cleared: true });
  });

  app.post('/api/send', async (req, res) => {
    const {
      method = 'GET',
      url,
      headers = {},
      body = '',
      followRedirects = false,
      useCookieJar = false,
      label = 'repeater',
    } = req.body || {};
    if (!url) {
      return res.status(400).json({ error: 'Missing url' });
    }
    try {
      const hops = await sendAndTrace(store, {
        method,
        url,
        headers,
        body,
        followRedirects: Boolean(followRedirects),
        cookieJar: useCookieJar ? cookieJar : null,
        label,
      });
      return res.json({ hops, cookies: cookieJar.list() });
    } catch (err) {
      return res.status(502).json({ error: err.message });
    }
  });

  app.post('/api/mutations/redirect-uri', (req, res) => {
    const { baseRedirectUri = 'http://localhost:3000/callback', attackerHost = 'attacker.example' } = req.body || {};
    res.json({ mutations: generateRedirectUriMutations(baseRedirectUri, attackerHost) });
  });

  app.post('/api/mutations/redirect-uri/batch', async (req, res) => {
    const {
      baseUrl,
      headers = {},
      attackerHost = 'attacker.example',
      mutationIds,
      useCookieJar = true,
    } = req.body || {};
    if (!baseUrl) {
      return res.status(400).json({ error: 'Missing baseUrl' });
    }
    try {
      const parsed = parseOAuthUrl(baseUrl);
      const baseRedirect = parsed.oauthParams.redirect_uri || 'http://localhost:3000/callback';
      let mutations = generateRedirectUriMutations(baseRedirect, attackerHost);
      if (Array.isArray(mutationIds) && mutationIds.length > 0) {
        const allow = new Set(mutationIds);
        mutations = mutations.filter((m) => allow.has(m.id));
      }
      const results = await batchTestRedirectUris(store, {
        baseUrl,
        headers,
        mutations,
        attackerHost,
        cookieJar: useCookieJar ? cookieJar : null,
      });
      return res.json({ results });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  });

  app.get('/api/mutations/custom-presets', (_req, res) => {
    res.json({ presets: getCustomFieldPresets() });
  });

  app.post('/api/mutations/custom/batch', async (req, res) => {
    const {
      method = 'GET',
      baseUrl,
      headers = {},
      body = '',
      targetLocation = 'query',
      paramName,
      payloads = [],
      useCookieJar = true,
    } = req.body || {};

    if (!baseUrl || !paramName || !Array.isArray(payloads) || payloads.length === 0) {
      return res.status(400).json({ error: 'baseUrl, paramName, and non-empty payloads array are required' });
    }

    try {
      new URL(baseUrl);
      const data = await batchTestCustomField(store, {
        method,
        baseUrl,
        headers,
        body,
        targetLocation,
        paramName,
        payloads: payloads.slice(0, 50),
        cookieJar: useCookieJar ? cookieJar : null,
      });
      return res.json(data);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  });

  app.post('/api/mutations/params/batch', async (req, res) => {
    const { baseUrl, headers = {}, mutationIds, useCookieJar = true } = req.body || {};
    if (!baseUrl) {
      return res.status(400).json({ error: 'Missing baseUrl' });
    }
    try {
      new URL(baseUrl);
      let mutations = getOAuthParameterMutations();
      if (Array.isArray(mutationIds) && mutationIds.length > 0) {
        const allow = new Set(mutationIds);
        mutations = mutations.filter((m) => allow.has(m.id));
      }
      const results = await batchTestOAuthParams(store, {
        baseUrl,
        headers,
        mutations,
        cookieJar: useCookieJar ? cookieJar : null,
      });
      return res.json({ results });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  });

  app.get('/api/mutations/custom-presets', (_req, res) => {
    res.json({ presets: getCustomFieldPresets() });
  });

  app.post('/api/mutations/custom/batch', async (req, res) => {
    const {
      method = 'GET',
      baseUrl,
      headers = {},
      body = '',
      targetLocation = 'query',
      paramName,
      payloads = [],
      useCookieJar = true,
    } = req.body || {};

    if (!baseUrl || !paramName || !Array.isArray(payloads) || payloads.length === 0) {
      return res.status(400).json({ error: 'baseUrl, paramName, and non-empty payloads array are required' });
    }

    try {
      new URL(baseUrl);
      const data = await batchTestCustomField(store, {
        method,
        baseUrl,
        headers,
        body,
        targetLocation,
        paramName,
        payloads: payloads.slice(0, 50),
        cookieJar: useCookieJar ? cookieJar : null,
      });
      return res.json(data);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  });

  app.post('/api/jwt/inspect', (req, res) => {
    const { token } = req.body || {};
    res.json(inspectJwt(token));
  });

  app.post('/api/jwt/verify', async (req, res) => {
    const { token, jwksUri, jwks, headers = {} } = req.body || {};
    if (!token) {
      return res.status(400).json({ error: 'Missing token' });
    }
    try {
      let keySet = jwks;
      if (!keySet && jwksUri) {
        const jwksRes = await fetch(jwksUri, {
          headers: { Accept: 'application/json', ...headers },
          signal: AbortSignal.timeout(10000),
        });
        if (!jwksRes.ok) {
          return res.status(502).json({ error: `Failed to fetch JWKS: HTTP ${jwksRes.status}` });
        }
        try {
          keySet = await jwksRes.json();
        } catch {
          return res.status(502).json({ error: 'JWKS endpoint did not return valid JSON' });
        }
      }
      return res.json(verifyJwtWithJwks(token, keySet));
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  });

  app.get('/api/mutations/token-list', (_req, res) => {
    res.json({ mutations: getTokenEndpointMutations() });
  });

  app.post('/api/mutations/token/batch', async (req, res) => {
    const { url, headers = {}, body = '', attackerHost = 'attacker.example', mutationIds, useCookieJar = true } = req.body || {};
    if (!url) {
      return res.status(400).json({ error: 'Missing url' });
    }
    try {
      new URL(url);
      let mutations = getTokenEndpointMutations();
      if (Array.isArray(mutationIds) && mutationIds.length > 0) {
        const allow = new Set(mutationIds);
        mutations = mutations.filter((m) => allow.has(m.id));
      }
      const results = await batchTestTokenEndpoint(store, {
        url,
        headers,
        body,
        mutations,
        attackerHost,
        cookieJar: useCookieJar ? cookieJar : null,
      });
      return res.json({ results });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  });

  // Local OAuth callback listener (supports GET query, #fragment, and POST form_post)
  app.post('/callback', express.urlencoded({ extended: false }), (req, res) => {
    const fullUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
    const bodyParams = req.body && typeof req.body === 'object' ? req.body : {};
    const parsed = parseOAuthUrl(fullUrl);
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
        body: new URLSearchParams(bodyParams).toString(),
        oauthParams: mergedParams,
      },
      response: {
        status: 200,
        statusText: 'OK',
        headers: { 'content-type': 'text/html' },
        location: null,
        body: '',
        oauthParams: mergedParams,
      },
      audit,
    });

    res.type('html').send('<!doctype html><html><body style="font-family:monospace;background:#0f172a;color:#e2e8f0;padding:24px;"><h2>OAuth form_post Callback Captured</h2><p>Logged to OAuth Workbench.</p></body></html>');
  });

  app.get('/callback', (req, res) => {
    const fullUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
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
        location: null,
        body: '',
        oauthParams: parsed.oauthParams,
      },
      audit,
    });

    res.type('html').send(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>OAuth Callback Captured</title></head>
<body style="font-family: ui-monospace, monospace; background:#0f172a; color:#e2e8f0; padding:24px;">
  <h2>OAuth Callback Captured</h2>
  <p>Query parameters were logged to OAuth Workbench.</p>
  <pre id="out"></pre>
  <script>
    const out = document.getElementById('out');
    out.textContent = window.location.href;
    if (window.location.hash && window.location.hash.length > 1) {
      fetch('/api/callback-fragment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fullUrl: window.location.href })
      });
    }
  </script>
</body>
</html>`);
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

  return { app, store, mockIdp, cookieJar };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const port = Number(process.env.PORT || 3000);
  const host = process.env.HOST || '127.0.0.1';
  const { app } = createApp();
  app.listen(port, host, () => {
    console.log(`OAuth Workbench listening on http://${host}:${port}`);
    console.log(`Mock IdP available at http://${host}:${port}/mock-idp/.well-known/openid-configuration`);
  });
}
