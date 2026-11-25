import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';
import {
  TraceStore,
  evaluateRedirectProbe,
  batchTestRedirectUris,
  batchTestCustomField,
  batchTestTokenEndpoint,
} from '../src/tracer.js';
import { generateRedirectUriMutations, getTokenEndpointMutations } from '../src/oauth/payloads.js';

async function startServer() {
  const { app, mockIdp } = createApp();
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}`, mockIdp };
}

test('TraceStore enforces maxEntries ring buffer, clear, and unsubscribe', () => {
  const store = new TraceStore(3);
  const events = [];
  const unsub = store.subscribe((ev, data) => events.push({ ev, id: data.id }));

  store.add({ id: '1' });
  store.add({ id: '2' });
  store.add({ id: '3' });
  store.add({ id: '4' });

  assert.deepEqual(store.list().map((e) => e.id), ['4', '3', '2']);
  unsub();
  store.clear();
  assert.equal(store.list().length, 0);
  assert.equal(events.length, 4);
});

test('evaluateRedirectProbe handles ACCEPTED_REDIRECT and relative error paths', () => {
  const redirNoCred = evaluateRedirectProbe({
    status: 302,
    location: 'https://sub.evil.test/landing',
    mutatedUri: 'https://sub.evil.test/landing',
    attackerHost: 'evil.test',
  });
  assert.equal(redirNoCred.accepted, true);
  assert.equal(redirNoCred.verdict, 'ACCEPTED_REDIRECT');

  const relErr = evaluateRedirectProbe({
    status: 302,
    location: '/error?error=invalid_request',
    mutatedUri: 'https://evil.test/cb',
    attackerHost: 'evil.test',
  });
  assert.equal(relErr.accepted, false);
  assert.equal(relErr.verdict, 'REDIRECT_ERROR');
});

test('batchTestRedirectUris runs all 28 payloads with expected strict vs weakPrefix verdicts', async () => {
  const { server, baseUrl, mockIdp } = await startServer();
  const store = new TraceStore();
  try {
    mockIdp.setConfig({ allowedRedirectPrefix: baseUrl, weakPrefixRedirect: false, allowOpenRedirect: false });
    const authUrl = `${baseUrl}/mock-idp/authorize?client_id=c1&redirect_uri=${encodeURIComponent(`${baseUrl}/callback`)}&response_type=code&state=s1`;
    const allMuts = generateRedirectUriMutations(`${baseUrl}/callback`, 'evil.example');
    assert.equal(allMuts.length, 28);

    const strictRes = await batchTestRedirectUris(store, {
      baseUrl: authUrl,
      mutations: allMuts,
      attackerHost: 'evil.example',
    });
    assert.equal(strictRes.length, 28);
    const mustBlockStrict = new Set([
      'SUBDOMAIN_SUFFIX',
      'WHITELIST_SUBSTRING_PATH',
      'AUTHORITY_AT_SIGN',
      'AUTHORITY_AT_ENCODED',
      'BACKSLASH_CONFUSION',
      'DOUBLE_URL_ENCODE',
      'NULL_BYTE_TRUNCATION',
      'CUSTOM_SCHEME_MOBILE',
    ]);
    for (const r of strictRes) {
      if (mustBlockStrict.has(r.id)) {
        assert.equal(r.accepted, false, `Expected strict mode to block ${r.id}`);
      }
    }

    mockIdp.setConfig({ weakPrefixRedirect: true });
    const weakRes = await batchTestRedirectUris(store, {
      baseUrl: authUrl,
      mutations: allMuts,
      attackerHost: 'evil.example',
    });
    const acceptedCount = weakRes.filter((r) => r.accepted).length;
    assert.ok(acceptedCount >= 4 && acceptedCount < 28);
  } finally {
    server.close();
  }
});

test('batchTestCustomField fuzzes both query and JSON/form body and reports baseline errors', async () => {
  const { server, baseUrl } = await startServer();
  const store = new TraceStore();
  try {
    // 1. Form body fuzzing on /mock-idp/token
    const formRes = await batchTestCustomField(store, {
      method: 'POST',
      baseUrl: `${baseUrl}/mock-idp/token`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=authorization_code&code=invalid&client_id=c1',
      targetLocation: 'body',
      paramName: 'grant_type',
      payloads: ['authorization_code', 'client_credentials'],
    });
    assert.equal(formRes.baseline.status, 400);
    assert.equal(formRes.results[0].anomaly, false);
    assert.equal(formRes.results[1].anomaly, true);

    // 2. JSON body fuzzing on /api/parse
    const jsonRes = await batchTestCustomField(store, {
      method: 'POST',
      baseUrl: `${baseUrl}/api/parse`,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: 'https://auth.example/authorize?client_id=1' }),
      targetLocation: 'body',
      paramName: 'input',
      payloads: ['https://auth.example/authorize?client_id=1', 'invalid'],
    });
    assert.equal(jsonRes.baseline.status, 200);
    assert.equal(jsonRes.results[0].anomaly, false);
    assert.equal(jsonRes.results[1].status, 400);
    assert.equal(jsonRes.results[1].anomaly, true);

    // 3. Unreachable baseline throws clear error
    await assert.rejects(
      () =>
        batchTestCustomField(store, {
          method: 'GET',
          baseUrl: 'http://127.0.0.1:1/unreachable',
          paramName: 'x',
          payloads: ['1'],
        }),
      /Baseline request failed/
    );
  } finally {
    server.close();
  }
});

test('batchTestTokenEndpoint detects code replay rejection and handles lowercase content-type', async () => {
  const { server, baseUrl, mockIdp } = await startServer();
  const store = new TraceStore();
  mockIdp.setConfig({ allowedRedirectPrefix: baseUrl });
  try {
    const authRes = await fetch(
      `${baseUrl}/mock-idp/authorize?client_id=c1&redirect_uri=${encodeURIComponent(`${baseUrl}/callback`)}&response_type=code&state=s1`,
      { redirect: 'manual' }
    );
    const code = new URL(authRes.headers.get('location')).searchParams.get('code');

    const replayMut = getTokenEndpointMutations().filter((m) => m.id === 'TOKEN_REPLAY_CODE');
    const results = await batchTestTokenEndpoint(store, {
      url: `${baseUrl}/mock-idp/token`,
      headers: { 'content-type': 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${baseUrl}/callback`,
        client_id: 'c1',
      }).toString(),
      mutations: replayMut,
    });
    assert.equal(results.length, 1);
    assert.equal(results[0].status, 400);
    assert.equal(results[0].accepted, false);
    assert.equal(results[0].verdict, 'BLOCKED');
  } finally {
    server.close();
  }
});
