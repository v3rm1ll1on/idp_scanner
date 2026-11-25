import test from 'node:test';
import assert from 'node:assert/strict';
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
  } finally {
    server.close();
  }
});
