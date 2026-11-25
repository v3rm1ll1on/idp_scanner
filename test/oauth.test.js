import test from 'node:test';
import assert from 'node:assert/strict';
import { parseOAuthUrl, parseRawHttpRequest } from '../src/oauth/parser.js';
import { inspectJwt, encodeBase64Url } from '../src/oauth/jwt.js';
import { RedirectUriMutationType, generateRedirectUriMutations } from '../src/oauth/payloads.js';
import { auditOAuthContext } from '../src/oauth/analyzer.js';

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
