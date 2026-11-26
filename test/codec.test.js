import test from 'node:test';
import assert from 'node:assert/strict';

import {
  urlEncodeComponent,
  urlDecodeComponent,
  urlDoubleEncode,
  encodeQueryValues,
  decodeQueryValues,
  extractQueryParams,
} from '../public/js/codec.js';

test('urlEncodeComponent and urlDecodeComponent handle OAuth redirect_uri & plus spaces', () => {
  const raw = 'https://evil.com/cb?a=1&b=hello world';
  const encoded = urlEncodeComponent(raw);
  assert.equal(encoded, 'https%3A%2F%2Fevil.com%2Fcb%3Fa%3D1%26b%3Dhello%20world');
  assert.equal(urlDecodeComponent(encoded), raw);
  assert.equal(urlDecodeComponent('openid+profile+email', true), 'openid profile email');
  assert.equal(urlDecodeComponent('a+b', false), 'a+b');
});

test('urlDoubleEncode produces %25XX sequences', () => {
  assert.equal(urlDoubleEncode('/../admin'), '%252F..%252Fadmin');
});

test('encodeQueryValues and decodeQueryValues preserve base URL and keys', () => {
  const url = 'https://auth.example.com/authorize?client_id=demo&redirect_uri=https://evil.com/cb?x=1&scope=openid profile#frag';
  const encoded = encodeQueryValues(url);
  assert.equal(
    encoded,
    'https://auth.example.com/authorize?client_id=demo&redirect_uri=https%3A%2F%2Fevil.com%2Fcb%3Fx%3D1&scope=openid%20profile#frag',
  );
  assert.equal(decodeQueryValues(encoded), url);
});

test('extractQueryParams decodes query parameters safely including malformed percent sequences', () => {
  const params = extractQueryParams('https://auth.example.com/cb?code=abc%2B123&scope=openid+email&bad=%ZZ');
  assert.deepEqual(params, [
    { key: 'code', rawValue: 'abc%2B123', decodedValue: 'abc+123' },
    { key: 'scope', rawValue: 'openid+email', decodedValue: 'openid email' },
    { key: 'bad', rawValue: '%ZZ', decodedValue: '%ZZ' },
  ]);
});
