import crypto from 'node:crypto';

/**
 * Decodes a base64url-encoded string to UTF-8.
 * @param {string} input
 * @returns {string}
 */
export function decodeBase64Url(input) {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, 'base64').toString('utf8');
}

/**
 * Encodes a string or object as base64url.
 * @param {string|object} input
 * @returns {string}
 */
export function encodeBase64Url(input) {
  const str = typeof input === 'string' ? input : JSON.stringify(input);
  return Buffer.from(str, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Parses and audits a JWT string without verifying cryptographic signatures.
 * @param {string} token
 * @returns {object}
 */
export function inspectJwt(token) {
  if (typeof token !== 'string' || !token.trim()) {
    return { valid: false, error: 'Empty token' };
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    return { valid: false, isOpaque: true, error: `Expected 3 JWT segments, got ${parts.length}` };
  }

  try {
    const header = JSON.parse(decodeBase64Url(parts[0]));
    const payload = JSON.parse(decodeBase64Url(parts[1]));
    const signature = parts[2];
    const findings = [];

    const alg = String(header.alg || '');
    if (!alg || alg.toLowerCase() === 'none') {
      findings.push({
        severity: 'HIGH',
        code: 'JWT_ALG_NONE',
        title: 'JWT uses unsecured "alg: none"',
        detail: 'Token header specifies alg=none or omits alg; signature verification may be bypassed.',
      });
    }

    if (!signature) {
      findings.push({
        severity: 'HIGH',
        code: 'JWT_EMPTY_SIGNATURE',
        title: 'JWT has an empty signature segment',
        detail: 'No cryptographic signature is attached to this token.',
      });
    }

    if (header.jwk || header.jku || header.x5u) {
      findings.push({
        severity: 'MEDIUM',
        code: 'JWT_EMBEDDED_KEY_HEADER',
        title: 'JWT contains embedded/remote key header (jwk/jku/x5u)',
        detail: 'Verify that the server enforces a strict allowlist on jku/x5u and ignores untrusted inline jwk headers.',
      });
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number') {
      if (payload.exp < now) {
        findings.push({
          severity: 'INFO',
          code: 'JWT_EXPIRED',
          title: 'JWT is expired',
          detail: `Expired at ${new Date(payload.exp * 1000).toISOString()}.`,
        });
      }
    } else {
      findings.push({
        severity: 'LOW',
        code: 'JWT_NO_EXP',
        title: 'JWT lacks "exp" claim',
        detail: 'Tokens without an expiration claim may remain valid indefinitely.',
      });
    }

    if (!payload.aud) {
      findings.push({
        severity: 'LOW',
        code: 'JWT_NO_AUD',
        title: 'JWT lacks "aud" (audience) claim',
        detail: 'Missing audience claim can enable cross-service token replay.',
      });
    }

    return {
      valid: true,
      isOpaque: false,
      header,
      payload,
      signature,
      raw: token.trim(),
      expiresAt: typeof payload.exp === 'number' ? new Date(payload.exp * 1000).toISOString() : null,
      issuedAt: typeof payload.iat === 'number' ? new Date(payload.iat * 1000).toISOString() : null,
      findings,
    };
  } catch (err) {
    return { valid: false, isOpaque: true, error: `Failed to decode JWT: ${err.message}` };
  }
}

/**
 * Extracts potential JWTs from an object, query params, or raw text.
 * @param {string|object} source
 * @returns {Array<{label: string, token: string, inspection: object}>}
 */
export function extractAndInspectJwts(source) {
  const results = [];
  const seen = new Set();
  const jwtRegex = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])/g;

  const scanText = (text, labelPrefix) => {
    if (typeof text !== 'string') return;
    const matches = text.match(jwtRegex) || [];
    for (const token of matches) {
      if (seen.has(token)) continue;
      seen.add(token);
      const inspection = inspectJwt(token);
      if (inspection.valid) {
        results.push({ label: labelPrefix, token, inspection });
      }
    }
  };

  if (typeof source === 'string') {
    scanText(source, 'extracted');
  } else if (source && typeof source === 'object') {
    for (const [key, value] of Object.entries(source)) {
      if (typeof value === 'string') {
        scanText(value, key);
      } else if (value && typeof value === 'object') {
        scanText(JSON.stringify(value), key);
      }
    }
  }

  return results;
}

const ALG_TO_NODE_HASH = {
  RS256: 'RSA-SHA256',
  RS384: 'RSA-SHA384',
  RS512: 'RSA-SHA512',
  ES256: 'SHA256',
  ES384: 'SHA384',
  ES512: 'SHA512',
  PS256: 'RSA-SHA256',
};

/**
 * Verifies a JWT signature against a JWKS key set using Node's native crypto.
 * @param {string} token
 * @param {object} jwks
 * @returns {{verified: boolean, alg: string, kid: string|null, reason: string}}
 */
export function verifyJwtWithJwks(token, jwks) {
  const insp = inspectJwt(token);
  if (!insp.valid) {
    return { verified: false, alg: '', kid: null, reason: insp.error || 'Invalid JWT' };
  }

  const alg = String(insp.header.alg || '');
  const kid = insp.header.kid || null;
  if (!alg || alg.toLowerCase() === 'none') {
    return { verified: false, alg, kid, reason: 'Unsecured alg=none cannot be cryptographically verified' };
  }

  const hashAlg = ALG_TO_NODE_HASH[alg];
  if (!hashAlg) {
    return { verified: false, alg, kid, reason: `Unsupported asymmetric JWS alg "${alg}" (supports RS*/ES*/PS256)` };
  }

  const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
  if (keys.length === 0) {
    return { verified: false, alg, kid, reason: 'JWKS contains no keys' };
  }

  const candidates = kid ? keys.filter((k) => k.kid === kid) : keys;
  if (kid && candidates.length === 0) {
    return { verified: false, alg, kid, reason: `No key with kid="${kid}" found in JWKS` };
  }

  const parts = token.trim().split('.');
  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
  const sigBuf = Buffer.from(parts[2], 'base64url');

  for (const jwk of candidates) {
    if (jwk.kty === 'oct') continue;
    try {
      const pubKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      const verifyOpts = alg === 'PS256'
        ? { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }
        : alg.startsWith('ES')
          ? { key: pubKey, dsaEncoding: 'ieee-p1363' }
          : pubKey;
      const ok = crypto.verify(hashAlg, signingInput, verifyOpts, sigBuf);
      if (ok) {
        return {
          verified: true,
          alg,
          kid: jwk.kid || kid,
          reason: `Signature verified against JWKS key${jwk.kid ? ` (${jwk.kid})` : ''}`,
        };
      }
    } catch {
      // Try next candidate key
    }
  }

  return { verified: false, alg, kid, reason: 'Signature did not match any key in JWKS' };
}
