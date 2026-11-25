import test from 'node:test';
import assert from 'node:assert/strict';
import { parseOAuthUrl, parseRawHttpRequest } from '../src/oauth/parser.js';
import { inspectJwt, encodeBase64Url } from '../src/oauth/jwt.js';
import { RedirectUriMutationType, generateRedirectUriMutations } from '../src/oauth/payloads.js';
import { auditOAuthContext } from '../src/oauth/analyzer.js';
import { evaluateRedirectProbe, buildUrlWithRawRedirectUri } from '../src/tracer.js';
import { parseSetCookieHeader, CookieJar } from '../src/oauth/cookies.js';

test('parseOAuthUrl extracts query and fragment parameters', () => {
  const parsed = parseOAuthUrl(
    'https://app.example.com/callback#access_token=tok123&token_type=Bearer&state=xyz'
  );
  assert.equal(parsed.flowKind, 'implicit_callback');
  assert.equal(parsed.fragmentParams.access_token, 'tok123');
  assert.equal(parsed.oauthParams.state, 'xyz');
});

test('parseRawHttpRequest parses Burp-style POST token request', () => {
  const raw = [
    'POST /oauth/token HTTP/1.1',
    'Host: auth.example.com',
    'Content-Type: application/x-www-form-urlencoded',
    '',
    'grant_type=authorization_code&code=abc123&redirect_uri=https://app.example.com/cb',
  ].join('\r\n');

  const parsed = parseRawHttpRequest(raw);
  assert.equal(parsed.method, 'POST');
  assert.equal(parsed.url, 'https://auth.example.com/oauth/token');
  assert.equal(parsed.oauthParams.grant_type, 'authorization_code');
  assert.equal(parsed.oauthParams.code, 'abc123');
});

test('inspectJwt flags alg:none and missing claims', () => {
  const header = encodeBase64Url({ alg: 'none', typ: 'JWT' });
  const payload = encodeBase64Url({ sub: 'user-1' });
  const token = `${header}.${payload}.`;

  const res = inspectJwt(token);
  assert.equal(res.valid, true);
  const codes = res.findings.map((f) => f.code);
  assert.ok(codes.includes('JWT_ALG_NONE'));
  assert.ok(codes.includes('JWT_EMPTY_SIGNATURE'));
  assert.ok(codes.includes('JWT_NO_EXP'));
  assert.ok(codes.includes('JWT_NO_AUD'));
});

test('generateRedirectUriMutations covers all RedirectUriMutationType entries', () => {
  const mutations = generateRedirectUriMutations('https://client.example.org/cb', 'evil.test');
  const ids = new Set(mutations.map((m) => m.id));
  for (const enumVal of Object.values(RedirectUriMutationType)) {
    assert.ok(ids.has(enumVal), `Missing mutation for ${enumVal}`);
  }
  const atMut = mutations.find((m) => m.id === RedirectUriMutationType.AUTHORITY_AT_SIGN);
  assert.equal(atMut.uri, 'https://client.example.org@evil.test/cb');
});

test('auditOAuthContext flags implicit flow, missing state, and weak headers', () => {
  const audit = auditOAuthContext({
    oauthParams: { response_type: 'token', redirect_uri: 'http://app.example.org/cb' },
    status: 302,
    responseHeaders: { 'set-cookie': 'sid=123; Path=/' },
    location: 'http://app.example.org/cb#access_token=abc',
  });
  const codes = audit.findings.map((f) => f.code);
  assert.ok(codes.includes('OAUTH_IMPLICIT_FLOW'));
  assert.ok(codes.includes('OAUTH_MISSING_STATE'));
  assert.ok(codes.includes('OAUTH_INSECURE_REDIRECT_SCHEME'));
  assert.ok(codes.includes('OAUTH_TOKEN_IN_REDIRECT'));
  assert.ok(codes.includes('HTTP_WEAK_COOKIE_FLAGS'));
});

test('evaluateRedirectProbe distinguishes credential redirect vs error redirect vs blocked', () => {
  const cred = evaluateRedirectProbe({
    status: 302,
    location: 'https://app.example.com@evil.test/cb?code=123',
    mutatedUri: 'https://app.example.com@evil.test/cb',
    attackerHost: 'evil.test',
  });
  assert.equal(cred.accepted, true);
  assert.equal(cred.verdict, 'ACCEPTED_WITH_CREDENTIAL');

  const errRedirect = evaluateRedirectProbe({
    status: 302,
    location: 'https://evil.test/cb?error=invalid_request',
    mutatedUri: 'https://evil.test/cb',
    attackerHost: 'evil.test',
  });
  assert.equal(errRedirect.accepted, false);
  assert.equal(errRedirect.verdict, 'REDIRECT_ERROR');

  const blocked = evaluateRedirectProbe({
    status: 400,
    location: '',
    mutatedUri: 'https://evil.test/cb',
    attackerHost: 'evil.test',
  });
  assert.equal(blocked.accepted, false);
  assert.equal(blocked.verdict, 'BLOCKED');
});

test('parseSetCookieHeader and CookieJar handle attributes, scoping, and expiry', () => {
  const parsed = parseSetCookieHeader('sso_sid=xyz123; Domain=.example.com; Path=/; HttpOnly; SameSite=None');
  assert.equal(parsed.name, 'sso_sid');
  assert.equal(parsed.value, 'xyz123');
  assert.equal(parsed.domain, '.example.com');
  assert.equal(parsed.httpOnly, true);
  assert.equal(parsed.sameSite, 'None');
  assert.equal(parsed.secure, false);

  const jar = new CookieJar();
  jar.setFromHeaders('https://auth.example.com/authorize', [
    'sso_sid=xyz123; Domain=.example.com; Path=/; HttpOnly; SameSite=Lax',
    'host_only=abc; Path=/authorize',
  ]);

  assert.equal(jar.getCookieHeader('https://app.example.com/callback'), 'sso_sid=xyz123');
  assert.equal(jar.getCookieHeader('https://auth.example.com/authorize'), 'sso_sid=xyz123; host_only=abc');
  assert.equal(jar.getCookieHeader('https://unrelated.org/'), null);

  jar.clear();
  assert.equal(jar.list().length, 0);
});

test('buildUrlWithRawRedirectUri preserves %XX sequences without double-encoding', () => {
  const out = buildUrlWithRawRedirectUri(
    'https://auth.example.com/authorize?client_id=c1&redirect_uri=https://app.example.com/cb&state=s1',
    'https://app.example.com/cb%0d%0aX-Test:%201#frag'
  );
  assert.ok(out.includes('redirect_uri=https://app.example.com/cb%0d%0aX-Test:%201%23frag'));
  assert.ok(!out.includes('%250d%250a'));
});
