import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { createApp, generateSelfSignedCert } from '../src/server.js';
import { RedirectUriMutationType } from '../src/oauth/payloads.js';

async function startTestServer() {
  const { app, mockIdp } = createApp();
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}`, mockIdp };
}

test('Discovery, full OAuth flow, and redirect_uri batch probe work end-to-end', async () => {
  const { server, baseUrl, mockIdp } = await startTestServer();
  mockIdp.setConfig({ allowedRedirectPrefix: baseUrl });
  try {
    // 1. OIDC Discovery
    const discRes = await fetch(`${baseUrl}/api/discover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuerUrl: `${baseUrl}/mock-idp` }),
    });
    assert.equal(discRes.status, 200);
    const disc = await discRes.json();
    assert.equal(disc.summary.authorization_endpoint, `${baseUrl}/mock-idp/authorize`);

    // 2. Authorize -> Callback hop trace
    const authUrl = `${baseUrl}/mock-idp/authorize?client_id=test-client&redirect_uri=${encodeURIComponent(
      `${baseUrl}/callback`
    )}&response_type=code&scope=openid%20profile&state=test_state_999`;

    const sendRes = await fetch(`${baseUrl}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'GET', url: authUrl, followRedirects: true }),
    });
    assert.equal(sendRes.status, 200);
    const sendData = await sendRes.json();
    assert.equal(sendData.hops.length, 2);
    const code = sendData.hops[0].response.oauthParams.code;
    assert.ok(code);

    // 3. Token exchange
    const tokenRes = await fetch(`${baseUrl}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: 'POST',
        url: `${baseUrl}/mock-idp/token`,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: `${baseUrl}/callback`,
          client_id: 'test-client',
        }).toString(),
      }),
    });
    const tokenData = await tokenRes.json();
    assert.equal(tokenData.hops[0].response.status, 200);
    assert.ok(tokenData.hops[0].audit.jwts.length >= 2);

    // 4. Redirect-URI batch probe (strict mode -> external redirect blocked)
    mockIdp.setConfig({ weakPrefixRedirect: false, allowOpenRedirect: false });
    const strictBatchRes = await fetch(`${baseUrl}/api/mutations/redirect-uri/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: authUrl,
        attackerHost: 'evil.example',
        mutationIds: [RedirectUriMutationType.SUBDOMAIN_SUFFIX, RedirectUriMutationType.AUTHORITY_AT_SIGN],
      }),
    });
    const strictBatch = await strictBatchRes.json();
    assert.equal(strictBatch.results.every((r) => r.accepted === false), true);

    // 4b. weakPrefixRedirect -> path traversal passes, external authority @ fails
    mockIdp.setConfig({ weakPrefixRedirect: true, allowOpenRedirect: false });
    const weakBatchRes = await fetch(`${baseUrl}/api/mutations/redirect-uri/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: authUrl,
        attackerHost: 'evil.example',
        mutationIds: [
          RedirectUriMutationType.PATH_TRAVERSAL_DOTDOT,
          RedirectUriMutationType.WHITELIST_SUBSTRING_PATH,
        ],
      }),
    });
    const weakBatch = await weakBatchRes.json();
    assert.equal(weakBatch.results.find((r) => r.id === RedirectUriMutationType.PATH_TRAVERSAL_DOTDOT).accepted, true);
    assert.equal(weakBatch.results.find((r) => r.id === RedirectUriMutationType.WHITELIST_SUBSTRING_PATH).accepted, false);

    // 5. Toggle allowOpenRedirect -> external redirect accepted
    mockIdp.setConfig({ allowOpenRedirect: true });
    const openBatchRes = await fetch(`${baseUrl}/api/mutations/redirect-uri/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: authUrl,
        attackerHost: 'evil.example',
        mutationIds: [RedirectUriMutationType.SUBDOMAIN_SUFFIX, RedirectUriMutationType.AUTHORITY_AT_SIGN],
      }),
    });
    const openBatch = await openBatchRes.json();
    assert.equal(openBatch.results.every((r) => r.accepted === true), true);
    assert.equal(openBatch.results.every((r) => r.verdict === 'ACCEPTED_WITH_CREDENTIAL'), true);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('PKCE S256, alg:none toggle, fragment capture, and SSE stream work', async () => {
  const { server, baseUrl, mockIdp } = await startTestServer();
  mockIdp.setConfig({ allowedRedirectPrefix: baseUrl, allowAlgNone: true });
  try {
    // 1. SSE stream receives live trace when /callback is hit
    const controller = new AbortController();
    const sseRes = await fetch(`${baseUrl}/api/traces/stream`, { signal: controller.signal });
    assert.equal(sseRes.status, 200);
    const reader = sseRes.body.getReader();
    const decoder = new TextDecoder();

    // Read initial connected event
    const firstChunk = await reader.read();
    assert.ok(decoder.decode(firstChunk.value).includes('event: connected'));

    // Trigger /callback
    const cbRes = await fetch(`${baseUrl}/callback?code=live_cb_code&state=s1`);
    assert.equal(cbRes.status, 200);

    const secondChunk = await reader.read();
    const sseText = decoder.decode(secondChunk.value);
    assert.ok(sseText.includes('event: trace'));
    assert.ok(sseText.includes('live_cb_code'));
    controller.abort();

    // 2. Fragment capture endpoint
    const fragRes = await fetch(`${baseUrl}/api/callback-fragment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fullUrl: `${baseUrl}/callback#access_token=frag_tok&state=s2` }),
    });
    const fragData = await fragRes.json();
    assert.equal(fragData.captured, true);
    assert.equal(fragData.oauthParams.access_token, 'frag_tok');

    // 3. PKCE S256 positive & negative test + alg:none JWT output
    const verifier = 'test_verifier_1234567890_abcdef';
    const challenge = crypto
      .createHash('sha256')
      .update(verifier)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const pkceAuthUrl = `${baseUrl}/mock-idp/authorize?client_id=pkce-client&redirect_uri=${encodeURIComponent(
      `${baseUrl}/callback`
    )}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&state=pkce1`;

    const authHopRes = await fetch(`${baseUrl}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'GET', url: pkceAuthUrl, followRedirects: false }),
    });
    const authHopData = await authHopRes.json();
    const pkceCode = authHopData.hops[0].response.oauthParams.code;
    assert.ok(pkceCode);

    const tokenRes = await fetch(`${baseUrl}/mock-idp/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: pkceCode,
        redirect_uri: `${baseUrl}/callback`,
        client_id: 'pkce-client',
        code_verifier: verifier,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const tokenJson = await tokenRes.json();
    const header = JSON.parse(Buffer.from(tokenJson.access_token.split('.')[0], 'base64url').toString('utf8'));
    assert.equal(header.alg, 'none');

    // 4. Cookie jar captures Set-Cookie on /mock-idp/authorize and forwards it on subsequent hops/requests
    const jarSendRes = await fetch(`${baseUrl}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: 'GET',
        url: pkceAuthUrl,
        followRedirects: true,
        useCookieJar: true,
      }),
    });
    const jarSendData = await jarSendRes.json();
    assert.equal(jarSendData.hops.length, 2);
    assert.equal(jarSendData.hops[0].response.cookies[0].name, 'mock_idp_session');
    assert.ok(jarSendData.hops[1].request.headers.Cookie.includes('mock_idp_session=sess_demo_123'));
    assert.equal(jarSendData.cookies.length, 1);

    const clearCookiesRes = await fetch(`${baseUrl}/api/cookies`, { method: 'DELETE' });
    assert.equal(clearCookiesRes.status, 200);
    const afterClear = await (await fetch(`${baseUrl}/api/cookies`)).json();
    assert.equal(afterClear.cookies.length, 0);

    // 5. Authorization code replay must fail on second exchange & missing code_verifier must fail
    const replayAuth = await fetch(`${baseUrl}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'GET', url: pkceAuthUrl, followRedirects: false }),
    });
    const replayCode = (await replayAuth.json()).hops[0].response.oauthParams.code;

    const noVerifierRes = await fetch(`${baseUrl}/mock-idp/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: replayCode,
        redirect_uri: `${baseUrl}/callback`,
        client_id: 'pkce-client',
      }).toString(),
    });
    assert.equal(noVerifierRes.status, 400);

    // 6. Malformed & HPP array redirect_uri handling in Mock IdP (no 500 crash)
    mockIdp.setConfig({ allowOpenRedirect: true });
    const badRedirectRes = await fetch(
      `${baseUrl}/mock-idp/authorize?client_id=c1&redirect_uri=not-a-valid-url&state=s1`
    );
    assert.equal(badRedirectRes.status, 400);

    const hppRes = await fetch(
      `${baseUrl}/mock-idp/authorize?client_id=c1&redirect_uri=${encodeURIComponent(`${baseUrl}/callback`)}&redirect_uri=${encodeURIComponent('https://evil.example/cb')}&state=s1`,
      { redirect: 'manual' }
    );
    assert.equal(hppRes.status, 302);
    assert.ok(hppRes.headers.get('location').startsWith('https://evil.example/cb'));

    // 7. OAuth Param Fuzzer batch probe
    mockIdp.setConfig({ allowMissingState: true, allowImplicitDowngrade: true });
    const paramBatchRes = await fetch(`${baseUrl}/api/mutations/params/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: pkceAuthUrl,
        mutationIds: ['REMOVE_STATE', 'DOWNGRADE_IMPLICIT_TOKEN'],
      }),
    });
    assert.equal(paramBatchRes.status, 200);
    const paramBatch = await paramBatchRes.json();
    assert.equal(paramBatch.results.every((r) => r.accepted === true && r.verdict === 'ACCEPTED (RISK)'), true);

    mockIdp.setConfig({ allowMissingState: false, allowImplicitDowngrade: false });
    const strictParamRes = await fetch(`${baseUrl}/api/mutations/params/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: pkceAuthUrl,
        mutationIds: ['REMOVE_STATE', 'DOWNGRADE_IMPLICIT_TOKEN'],
      }),
    });
    const strictParamBatch = await strictParamRes.json();
    assert.equal(strictParamBatch.results.every((r) => r.accepted === false && r.verdict === 'BLOCKED'), true);

    // 8. Custom Field Fuzzer presets & batch anomaly detection
    const presetsRes = await fetch(`${baseUrl}/api/mutations/custom-presets`);
    assert.equal(presetsRes.status, 200);
    const presetsJson = await presetsRes.json();
    assert.ok(presetsJson.presets.length >= 3);

    const customBatchRes = await fetch(`${baseUrl}/api/mutations/custom/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: 'GET',
        baseUrl: pkceAuthUrl,
        targetLocation: 'query',
        paramName: 'client_id',
        payloads: ['pkce-client', ''],
      }),
    });
    assert.equal(customBatchRes.status, 200);
    const customBatch = await customBatchRes.json();
    assert.equal(customBatch.baseline.status, 302);
    assert.equal(customBatch.results[0].status, 302);
    assert.equal(customBatch.results[1].status, 400);
    assert.equal(customBatch.results[1].anomaly, true);
    assert.equal(customBatch.results[1].verdict, 'ANOMALY');

    // 9. Token Endpoint batch probe
    const tokBatchRes = await fetch(`${baseUrl}/api/mutations/token/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: `${baseUrl}/mock-idp/token`,
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: replayCode,
          redirect_uri: `${baseUrl}/callback`,
          client_id: 'pkce-client',
          code_verifier: verifier,
        }).toString(),
        mutationIds: ['TOKEN_STRIP_VERIFIER', 'TOKEN_WRONG_VERIFIER'],
      }),
    });
    assert.equal(tokBatchRes.status, 200);
    const tokBatch = await tokBatchRes.json();
    assert.equal(tokBatch.results.every((r) => r.accepted === false && r.verdict === 'BLOCKED'), true);

    // 10. POST /callback (response_mode=form_post) capture
    const formPostRes = await fetch(`${baseUrl}/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: 'form_post_code_1', state: 'fp_state' }).toString(),
    });
    assert.equal(formPostRes.status, 200);
    const tracesAfterPost = await (await fetch(`${baseUrl}/api/traces`)).json();
    assert.equal(tracesAfterPost.traces[0].request.oauthParams.code, 'form_post_code_1');

    // 11. /api/parse validation & /api/jwt/verify against live JWKS endpoint
    const badParse = await fetch(`${baseUrl}/api/parse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: 'GET /no-host HTTP/1.1' }),
    });
    assert.equal(badParse.status, 400);

    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    jwk.kid = 'live-rsa-1';
    const headerB64 = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'live-rsa-1' })).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify({ sub: 'u1' })).toString('base64url');
    const sigB64 = crypto.sign('RSA-SHA256', Buffer.from(`${headerB64}.${payloadB64}`), privateKey).toString('base64url');

    const jwksVerify = await fetch(`${baseUrl}/api/jwt/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: `${headerB64}.${payloadB64}.${sigB64}`, jwks: { keys: [jwk] } }),
    });
    assert.equal((await jwksVerify.json()).verified, true);

    // 12. Mock IdP /userinfo rejects invalid Bearer token
    const badUserinfo = await fetch(`${baseUrl}/mock-idp/userinfo`, {
      headers: { Authorization: 'Bearer invalid_tok' },
    });
    assert.equal(badUserinfo.status, 401);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('sendAndTrace redirect method rules (302 vs 307, custom scheme), Discovery fallback & jwksUri fetch', async () => {
  const { server, baseUrl } = await startTestServer();
  const { default: express } = await import('express');

  // Auxiliary target server for redirect, discovery fallback, and jwksUri tests
  const auxApp = express();
  auxApp.use(express.text({ type: '*/*' }));

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = 'aux-rsa-1';

  auxApp.post('/hop302', (_req, res) => res.redirect(302, '/echo'));
  auxApp.post('/hop307', (_req, res) => res.redirect(307, '/echo'));
  auxApp.all('/echo', (req, res) => res.json({ method: req.method, body: typeof req.body === 'string' ? req.body : '' }));
  auxApp.get('/hop-custom', (_req, res) => res.redirect(302, 'myapp://callback?code=1'));

  auxApp.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.json({ issuer: 'https://custom-oauth.example', authorization_endpoint: 'https://custom-oauth.example/auth' });
  });
  auxApp.get('/protected/.well-known/openid-configuration', (req, res) => {
    const expected = `Basic ${Buffer.from('cid:csec').toString('base64')}`;
    if (req.get('Authorization') !== expected) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    return res.json({ issuer: 'https://protected.example', authorization_endpoint: 'https://protected.example/auth' });
  });
  auxApp.get('/jwks.json', (_req, res) => res.json({ keys: [jwk] }));
  auxApp.get('/jwks-html', (_req, res) => res.type('html').send('<html>error</html>'));

  const auxServer = await new Promise((resolve) => {
    const s = auxApp.listen(0, '127.0.0.1', () => resolve(s));
  });
  const auxBase = `http://127.0.0.1:${auxServer.address().port}`;

  try {
    // 1. 302 switches POST -> GET and drops body; 307 preserves POST + body
    const res302 = await (
      await fetch(`${baseUrl}/api/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: 'POST', url: `${auxBase}/hop302`, body: 'secret=1', followRedirects: true }),
      })
    ).json();
    assert.equal(res302.hops.length, 2);
    assert.deepEqual(JSON.parse(res302.hops[1].response.body), { method: 'GET', body: '' });

    const res307 = await (
      await fetch(`${baseUrl}/api/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: 'POST', url: `${auxBase}/hop307`, body: 'secret=1', followRedirects: true }),
      })
    ).json();
    assert.equal(res307.hops.length, 2);
    assert.deepEqual(JSON.parse(res307.hops[1].response.body), { method: 'POST', body: 'secret=1' });

    // 2. Custom scheme redirect stops cleanly after 1 hop
    const resCustom = await (
      await fetch(`${baseUrl}/api/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: 'GET', url: `${auxBase}/hop-custom`, followRedirects: true }),
      })
    ).json();
    assert.equal(resCustom.hops.length, 1);
    assert.equal(resCustom.hops[0].response.location, 'myapp://callback?code=1');

    // 3. Discovery fallback to /.well-known/oauth-authorization-server
    const discFallback = await (
      await fetch(`${baseUrl}/api/discover`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ issuerUrl: auxBase }),
      })
    ).json();
    assert.equal(discFallback.summary.issuer, 'https://custom-oauth.example');

    // 4. /api/jwt/verify via live jwksUri (valid + HTML 502 + 404 502)
    const hB64 = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'aux-rsa-1' })).toString('base64url');
    const pB64 = Buffer.from(JSON.stringify({ sub: 'u2' })).toString('base64url');
    const sB64 = crypto.sign('RSA-SHA256', Buffer.from(`${hB64}.${pB64}`), privateKey).toString('base64url');
    const jwt = `${hB64}.${pB64}.${sB64}`;

    const okVerify = await (
      await fetch(`${baseUrl}/api/jwt/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: jwt, jwksUri: `${auxBase}/jwks.json` }),
      })
    ).json();
    assert.equal(okVerify.verified, true);

    const htmlVerifyRes = await fetch(`${baseUrl}/api/jwt/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: jwt, jwksUri: `${auxBase}/jwks-html` }),
    });
    assert.equal(htmlVerifyRes.status, 502);

    const notFoundVerifyRes = await fetch(`${baseUrl}/api/jwt/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: jwt, jwksUri: `${auxBase}/missing.json` }),
    });
    assert.equal(notFoundVerifyRes.status, 502);

    // 5. Discovery with Basic Auth header
    const noAuthDisc = await fetch(`${baseUrl}/api/discover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuerUrl: `${auxBase}/protected` }),
    });
    assert.equal(noAuthDisc.status, 404);

    const basicHeader = `Basic ${Buffer.from('cid:csec').toString('base64')}`;
    const authDisc = await (
      await fetch(`${baseUrl}/api/discover`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issuerUrl: `${auxBase}/protected`,
          headers: { Authorization: basicHeader },
        }),
      })
    ).json();
    assert.equal(authDisc.summary.issuer, 'https://protected.example');
  } finally {
    auxServer.closeAllConnections?.();
    auxServer.close();
    server.closeAllConnections?.();
    server.close();
  }
});

test('Network settings: self-signed TLS bypass and upstream HTTP proxy routing work', async () => {
  const { server, baseUrl } = await startTestServer();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'owb-tls-'));
  const keyPath = path.join(tmpDir, 'key.pem');
  const certPath = path.join(tmpDir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', keyPath, '-out', certPath,
    '-days', '1', '-subj', '/CN=127.0.0.1',
  ]);

  const tlsServer = https.createServer(
    { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) },
    (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ tls: 'ok' }));
    }
  );
  await new Promise((resolve) => tlsServer.listen(0, '127.0.0.1', resolve));
  const tlsUrl = `https://127.0.0.1:${tlsServer.address().port}/health`;

  let proxySawTarget = null;
  const proxyServer = http.createServer((req, res) => {
    proxySawTarget = req.url;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ viaProxy: true }));
  });
  proxyServer.on('connect', (req, clientSocket, head) => {
    proxySawTarget = req.url;
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    const net = http;
    // Respond directly inside the tunnel with a minimal HTTP/1.1 200 response
    clientSocket.on('data', () => {
      clientSocket.end('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{"viaProxy":true}');
    });
    if (head && head.length) clientSocket.emit('data', head);
  });
  await new Promise((resolve) => proxyServer.listen(0, '127.0.0.1', resolve));
  const proxyUrl = `http://127.0.0.1:${proxyServer.address().port}`;

  try {
    // 1. Invalid proxyUrl rejected
    const badNet = await fetch(`${baseUrl}/api/network`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxyUrl: 'ftp://invalid-proxy' }),
    });
    assert.equal(badNet.status, 400);

    // 2. Strict TLS rejects self-signed cert
    const strictRes = await fetch(`${baseUrl}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'GET', url: tlsUrl }),
    });
    assert.equal(strictRes.status, 502);

    // 3. Enable insecureTls -> self-signed cert succeeds
    const enableTls = await fetch(`${baseUrl}/api/network`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ insecureTls: true }),
    });
    assert.equal((await enableTls.json()).insecureTls, true);

    const insecureRes = await fetch(`${baseUrl}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'GET', url: tlsUrl }),
    });
    assert.equal(insecureRes.status, 200);
    assert.equal(JSON.parse((await insecureRes.json()).hops[0].response.body).tls, 'ok');

    // 4. Enable upstream proxy -> request routes through proxy
    await fetch(`${baseUrl}/api/network`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxyUrl }),
    });
    const proxiedRes = await fetch(`${baseUrl}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'GET', url: 'http://target.internal/oauth/authorize?client_id=1' }),
    });
    assert.equal(proxiedRes.status, 200);
    assert.ok(proxySawTarget.includes('target.internal'));
  } finally {
    proxyServer.closeAllConnections?.();
    proxyServer.close();
    tlsServer.closeAllConnections?.();
    tlsServer.close();
    server.closeAllConnections?.();
    server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Global Basic Auth propagates across redirect chains without overriding explicit Authorization', async () => {
  const { server, baseUrl } = await startTestServer();
  const { default: express } = await import('express');

  const gateApp = express();
  const expectedBasic = `Basic ${Buffer.from('gateuser:gatepass').toString('base64')}`;

  gateApp.get('/start', (req, res) => {
    if (req.get('Authorization') !== expectedBasic) return res.status(401).send('gate1');
    return res.redirect(302, '/final');
  });
  gateApp.get('/final', (req, res) => {
    if (req.get('Authorization') !== expectedBasic) return res.status(401).send('gate2');
    return res.json({ gatePassed: true });
  });
  gateApp.get('/bearer-only', (req, res) => {
    return res.json({ authHeader: req.get('Authorization') || '' });
  });

  const gateServer = await new Promise((resolve) => {
    const s = gateApp.listen(0, '127.0.0.1', () => resolve(s));
  });
  const gateBase = `http://127.0.0.1:${gateServer.address().port}`;

  try {
    // 1. Set global Basic Auth (verify no password leak in GET /api/network)
    const setRes = await (
      await fetch(`${baseUrl}/api/network`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ basicAuth: { username: 'gateuser', password: 'gatepass' } }),
      })
    ).json();
    assert.equal(setRes.hasBasicAuth, true);
    assert.equal(setRes.basicAuthUser, 'gateuser');
    assert.equal(setRes.basicAuthHeader, undefined);

    // 2. Multi-hop redirect chain receives global Basic Auth on every hop
    const chainRes = await (
      await fetch(`${baseUrl}/api/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: 'GET', url: `${gateBase}/start`, followRedirects: true }),
      })
    ).json();
    assert.equal(chainRes.hops.length, 2);
    assert.equal(chainRes.hops[0].response.status, 302);
    assert.equal(chainRes.hops[1].response.status, 200);
    assert.equal(JSON.parse(chainRes.hops[1].response.body).gatePassed, true);

    // 3. Explicit Authorization: Bearer header is NOT overwritten by global Basic Auth
    const bearerRes = await (
      await fetch(`${baseUrl}/api/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: 'GET',
          url: `${gateBase}/bearer-only`,
          headers: { authorization: 'Bearer explicit_token_123' },
        }),
      })
    ).json();
    assert.equal(JSON.parse(bearerRes.hops[0].response.body).authHeader, 'Bearer explicit_token_123');

    // 4. Clear global Basic Auth -> gate rejects with 401
    const cleared = await (
      await fetch(`${baseUrl}/api/network`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ basicAuth: null }),
      })
    ).json();
    assert.equal(cleared.hasBasicAuth, false);

    const unauthRes = await (
      await fetch(`${baseUrl}/api/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: 'GET', url: `${gateBase}/start`, followRedirects: false }),
      })
    ).json();
    assert.equal(unauthRes.hops[0].response.status, 401);
  } finally {
    gateServer.closeAllConnections?.();
    gateServer.close();
    server.closeAllConnections?.();
    server.close();
  }
});

test('Host-based Catch-All Trap captures non-local Host requests on any path', async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    // Localhost unknown path still 404s
    const local404 = await fetch(`${baseUrl}/unknown-local-path`);
    assert.equal(local404.status, 404);

    // Non-local Host (simulated /etc/hosts attacker.example -> 127.0.0.1) is trapped on any path
    const { port } = server.address();
    const trapRes = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          path: '/evil/anything?code=stolen_999&state=s1',
          method: 'GET',
          headers: {
            Host: 'attacker.example:3000',
            Referer: 'https://idp.target.com/authorize',
          },
        },
        (res) => {
          let body = '';
          res.on('data', (c) => (body += c));
          res.on('end', () => resolve({ status: res.statusCode, body }));
        }
      );
      req.on('error', reject);
      req.end();
    });
    assert.equal(trapRes.status, 200);
    assert.ok(trapRes.body.includes('Attacker Trap Captured'));

    const traces = (await (await fetch(`${baseUrl}/api/traces`)).json()).traces;
    assert.equal(traces[0].label, 'attacker_trap');
    assert.equal(traces[0].request.oauthParams.code, 'stolen_999');
    assert.equal(traces[0].request.headers.referer, 'https://idp.target.com/authorize');

    // Also verify HTTPS listener with generated self-signed SAN cert
    const creds = generateSelfSignedCert(['localhost', 'attacker.example']);
    const httpsServer = https.createServer(creds, createApp().app);
    await new Promise((resolve) => httpsServer.listen(0, '127.0.0.1', resolve));
    try {
      const httpsPort = httpsServer.address().port;
      const sslHealth = await new Promise((resolve, reject) => {
        const req = https.request(
          { host: '127.0.0.1', port: httpsPort, path: '/api/health', rejectUnauthorized: false },
          (res) => {
            let b = '';
            res.on('data', (c) => (b += c));
            res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(b) }));
          }
        );
        req.on('error', reject);
        req.end();
      });
      assert.equal(sslHealth.status, 200);
      assert.equal(sslHealth.body.ok, true);
    } finally {
      httpsServer.closeAllConnections?.();
      httpsServer.close();
    }
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});
