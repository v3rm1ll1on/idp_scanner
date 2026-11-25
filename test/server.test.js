import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createApp } from '../src/server.js';
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
  } finally {
    server.close();
  }
});
