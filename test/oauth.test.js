import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { parseOAuthUrl, parseRawHttpRequest } from '../src/oauth/parser.js';
import { inspectJwt, encodeBase64Url, verifyJwtWithJwks } from '../src/oauth/jwt.js';
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

test('auditOAuthContext extracts JWT from Authorization request header', () => {
  const header = encodeBase64Url({ alg: 'none', typ: 'JWT' });
  const payload = encodeBase64Url({ sub: 'demo' });
  const jwt = `${header}.${payload}.`;

  const audit = auditOAuthContext({
    requestHeaders: { Authorization: `Bearer ${jwt}` },
    status: 200,
    responseHeaders: {},
  });
  assert.equal(audit.jwts.length, 1);
  assert.equal(audit.jwts[0].label, 'Authorization');
  assert.ok(audit.findings.some((f) => f.code === 'JWT_ALG_NONE'));
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
    status: 307,
    location: 'https://evil.test/cb?error=invalid_request',
    mutatedUri: 'https://evil.test/cb',
    attackerHost: 'evil.test',
  });
  assert.equal(errRedirect.accepted, false);
  assert.equal(errRedirect.verdict, 'REDIRECT_ERROR');
  assert.equal(errRedirect.errorDetail, 'error=invalid_request');

  const bodyErrRedirect = evaluateRedirectProbe({
    status: 307,
    location: 'https://evil.test/cb',
    mutatedUri: 'https://evil.test/cb',
    attackerHost: 'evil.test',
    responseBody: '{"error":"invalid_redirect_uri"}',
  });
  assert.equal(bodyErrRedirect.accepted, false);
  assert.equal(bodyErrRedirect.verdict, 'REDIRECT_ERROR');
  assert.equal(bodyErrRedirect.errorDetail, 'body:invalid_redirect_uri');

  const blocked = evaluateRedirectProbe({
    status: 400,
    location: '',
    mutatedUri: 'https://evil.test/cb',
    attackerHost: 'evil.test',
  });
  assert.equal(blocked.accepted, false);
  assert.equal(blocked.verdict, 'BLOCKED');

  // Ensure substring host match like not-evil.test does not false-positive as evil.test
  const substringFalsePos = evaluateRedirectProbe({
    status: 302,
    location: 'https://not-evil.test/cb',
    mutatedUri: 'https://evil.test/cb',
    attackerHost: 'evil.test',
  });
  assert.equal(substringFalsePos.accepted, false);
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
    'host_only=abc; Path=/auth',
  ]);

  assert.equal(jar.getCookieHeader('https://app.example.com/callback'), 'sso_sid=xyz123');
  assert.equal(jar.getCookieHeader('https://auth.example.com/authorize'), 'sso_sid=xyz123');
  assert.equal(jar.getCookieHeader('https://auth.example.com/auth/login'), 'sso_sid=xyz123; host_only=abc');
  assert.equal(jar.getCookieHeader('https://unrelated.org/'), null);

  // Reject cross-domain cookie injection
  jar.setFromHeaders('https://evil.org/login', ['hijack=1; Domain=example.com; Path=/']);
  assert.equal(jar.getCookieHeader('https://app.example.com/'), 'sso_sid=xyz123');

  // Delete cookie on past Expires header
  jar.setFromHeaders('https://auth.example.com/logout', [
    'sso_sid=; Domain=.example.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  ]);
  assert.equal(jar.getCookieHeader('https://app.example.com/callback'), null);

  jar.clear();
  assert.equal(jar.list().length, 0);
});

test('buildUrlWithRawRedirectUri encodes special chars when urlEncode=true while preserving %XX', () => {
  const encoded = buildUrlWithRawRedirectUri(
    'https://auth.example.com/authorize?client_id=c1&redirect_uri=https://app.example.com/cb&state=s1',
    'https://app.example.com/cb?next=https://evil.test%0d%0aX-Test:%201#frag',
    { urlEncode: true }
  );
  assert.ok(encoded.includes('redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb%3Fnext%3Dhttps%3A%2F%2Fevil.test%0d%0aX-Test%3A%201%23frag'));
  assert.ok(!encoded.includes('%250d%250a'));

  const rawOut = buildUrlWithRawRedirectUri(
    'https://auth.example.com/authorize?client_id=c1&redirect_uri=https://app.example.com/cb&state=s1',
    'https://app.example.com/cb%0d%0aX-Test:%201#frag',
    { urlEncode: false }
  );
  assert.ok(rawOut.includes('redirect_uri=https://app.example.com/cb%0d%0aX-Test:%201%23frag'));

  const hppOut = buildUrlWithRawRedirectUri(
    'https://auth.example.com/authorize?client_id=c1&redirect_uri=https://app.example.com/cb',
    'https://app.example.com/cb&redirect_uri=https://evil.test/cb',
    { isHpp: true, urlEncode: true }
  );
  assert.ok(hppOut.includes('redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&redirect_uri=https%3A%2F%2Fevil.test%2Fcb'));
});

test('verifyJwtWithJwks cryptographically verifies RS256 JWTs and rejects tampered payloads', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = 'rsa-test-1';

  const header = encodeBase64Url({ alg: 'RS256', typ: 'JWT', kid: 'rsa-test-1' });
  const payload = encodeBase64Url({ sub: 'pentester', iss: 'https://auth.example' });
  const sig = crypto
    .sign('RSA-SHA256', Buffer.from(`${header}.${payload}`), privateKey)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const validJwt = `${header}.${payload}.${sig}`;
  const okRes = verifyJwtWithJwks(validJwt, { keys: [jwk] });
  assert.equal(okRes.verified, true);
  assert.equal(okRes.kid, 'rsa-test-1');

  const tamperedPayload = encodeBase64Url({ sub: 'admin', iss: 'https://auth.example' });
  const badRes = verifyJwtWithJwks(`${header}.${tamperedPayload}.${sig}`, { keys: [jwk] });
  assert.equal(badRes.verified, false);

  const wrongKidHeader = encodeBase64Url({ alg: 'RS256', typ: 'JWT', kid: 'unknown-kid' });
  const wrongKidRes = verifyJwtWithJwks(`${wrongKidHeader}.${payload}.${sig}`, { keys: [jwk] });
  assert.equal(wrongKidRes.verified, false);
  assert.ok(wrongKidRes.reason.includes('unknown-kid'));
});

test('verifyJwtWithJwks verifies ES256 (ECDSA P-256) and rejects alg=none and oct keys', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = 'ec-1';

  const header = encodeBase64Url({ alg: 'ES256', typ: 'JWT', kid: 'ec-1' });
  const payload = encodeBase64Url({ sub: 'ec-user' });
  const sig = crypto
    .sign('SHA256', Buffer.from(`${header}.${payload}`), { key: privateKey, dsaEncoding: 'ieee-p1363' })
    .toString('base64url');

  const ok = verifyJwtWithJwks(`${header}.${payload}.${sig}`, { keys: [jwk] });
  assert.equal(ok.verified, true);
  assert.equal(ok.alg, 'ES256');

  const noneToken = `${encodeBase64Url({ alg: 'none' })}.${payload}.`;
  assert.equal(verifyJwtWithJwks(noneToken, { keys: [jwk] }).verified, false);
  assert.equal(verifyJwtWithJwks(`${header}.${payload}.${sig}`, { keys: [{ kty: 'oct', k: 'abc' }] }).verified, false);
});

test('parseRawHttpRequest handles IPv6, duplicate Cookie headers, JSON body, and invalid inputs', () => {
  const raw = [
    'POST /oauth/token HTTP/1.1',
    'Host: [::1]:3000',
    'Cookie: a=1',
    'Cookie: b=2',
    'Content-Type: application/json',
    '',
    '{"grant_type":"client_credentials","client_id":"c1"}',
  ].join('\n');

  const parsed = parseRawHttpRequest(raw);
  assert.equal(parsed.url, 'http://[::1]:3000/oauth/token');
  assert.equal(parsed.headers.Cookie, 'a=1; b=2');
  assert.equal(parsed.oauthParams.grant_type, 'client_credentials');

  assert.throws(() => parseRawHttpRequest('GET /only-path HTTP/1.1'), /Host header/);
  assert.throws(() => parseRawHttpRequest('   '), /Empty raw HTTP request/);
});

test('auditOAuthContext flags PKCE plain, missing PKCE, missing nonce, and cookie risks', () => {
  const audit = auditOAuthContext({
    oauthParams: {
      response_type: 'code id_token',
      state: '123',
      code_challenge: 'abc',
      code_challenge_method: 'plain',
    },
    status: 200,
    responseHeaders: {
      'set-cookie': 'sso=1; Domain=.example.com; Path=/; SameSite=None',
    },
  });
  const codes = audit.findings.map((f) => f.code);
  assert.ok(codes.includes('OAUTH_WEAK_STATE'));
  assert.ok(codes.includes('OAUTH_PKCE_PLAIN'));
  assert.ok(codes.includes('OIDC_MISSING_NONCE'));
  assert.ok(codes.includes('HTTP_COOKIE_SAMESITE_NONE_INSECURE'));
  assert.ok(codes.includes('HTTP_COOKIE_BROAD_DOMAIN'));
});

test('CookieJar respects Secure flag on non-HTTPS non-loopback origins and Max-Age=0 deletion', () => {
  const jar = new CookieJar();
  jar.setFromHeaders('https://app.example.com/login', ['sec_tok=abc; Path=/; Secure']);
  assert.equal(jar.getCookieHeader('http://app.example.com/api'), null);
  assert.equal(jar.getCookieHeader('https://app.example.com/api'), 'sec_tok=abc');

  jar.setFromHeaders('https://app.example.com/logout', ['sec_tok=; Path=/; Max-Age=0']);
  assert.equal(jar.getCookieHeader('https://app.example.com/api'), null);
});
