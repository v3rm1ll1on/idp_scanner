import { extractAndInspectJwts } from './jwt.js';
import { parseSetCookieHeader } from './cookies.js';

/**
 * Audits an OAuth/OIDC request or HTTP trace hop for security issues.
 * @param {object} context
 * @param {object} [context.oauthParams]
 * @param {object} [context.responseHeaders]
 * @param {Array<object>} [context.cookies]
 * @param {number} [context.status]
 * @param {string} [context.location]
 * @param {string} [context.responseBody]
 * @returns {{findings: Array<object>, jwts: Array<object>}}
 */
export function auditOAuthContext(context = {}) {
  const findings = [];
  const params = context.oauthParams || {};
  const headers = normalizeHeaders(context.responseHeaders || {});

  // 1. OAuth parameter checks
  if (params.response_type) {
    const rt = String(params.response_type).toLowerCase();
    if (rt.split(/\s+/).includes('token')) {
      findings.push({
        severity: 'HIGH',
        code: 'OAUTH_IMPLICIT_FLOW',
        title: 'Implicit / token-in-fragment response_type requested',
        detail: `response_type="${params.response_type}" exposes tokens in browser history, Referer headers, and JS context.`,
      });
    }

    if (!params.state) {
      findings.push({
        severity: 'MEDIUM',
        code: 'OAUTH_MISSING_STATE',
        title: 'Missing "state" parameter in authorization request',
        detail: 'Without a high-entropy state parameter, the OAuth callback may be vulnerable to Login CSRF.',
      });
    } else if (String(params.state).length < 8) {
      findings.push({
        severity: 'LOW',
        code: 'OAUTH_WEAK_STATE',
        title: 'Short "state" parameter detected',
        detail: `state="${params.state}" has low length (${String(params.state).length} chars).`,
      });
    }

    if (rt.includes('code')) {
      if (!params.code_challenge) {
        findings.push({
          severity: 'MEDIUM',
          code: 'OAUTH_NO_PKCE',
          title: 'Authorization Code flow without PKCE',
          detail: 'code_challenge is missing; public or misconfigured clients may be vulnerable to code interception.',
        });
      } else if (String(params.code_challenge_method || 'plain').toLowerCase() === 'plain') {
        findings.push({
          severity: 'MEDIUM',
          code: 'OAUTH_PKCE_PLAIN',
          title: 'PKCE uses "plain" challenge method',
          detail: 'S256 should be enforced instead of plain.',
        });
      }
    }

    if (rt.includes('id_token') && !params.nonce) {
      findings.push({
        severity: 'MEDIUM',
        code: 'OIDC_MISSING_NONCE',
        title: 'OIDC id_token requested without "nonce"',
        detail: 'Missing nonce weakens replay protection for ID tokens.',
      });
    }
  }

  if (params.redirect_uri && /^http:\/\//i.test(params.redirect_uri) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(params.redirect_uri)) {
    findings.push({
      severity: 'HIGH',
      code: 'OAUTH_INSECURE_REDIRECT_SCHEME',
      title: 'Non-HTTPS redirect_uri on non-loopback host',
      detail: `redirect_uri="${params.redirect_uri}" transmits authorization codes/tokens over plaintext HTTP.`,
    });
  }

  // 2. HTTP response header checks
  if (context.status) {
    if (!headers['cache-control'] || !/no-store/i.test(headers['cache-control'])) {
      findings.push({
        severity: 'LOW',
        code: 'HTTP_MISSING_NO_STORE',
        title: 'Response lacks "Cache-Control: no-store"',
        detail: 'Sensitive OAuth responses or tokens should not be cached by browsers or intermediaries.',
      });
    }

    if (!headers['referrer-policy']) {
      findings.push({
        severity: 'INFO',
        code: 'HTTP_MISSING_REFERRER_POLICY',
        title: 'Missing Referrer-Policy header',
        detail: 'Authorization codes or state values in URLs may leak via Referer if third-party assets are loaded.',
      });
    }

    const parsedCookies = Array.isArray(context.cookies)
      ? context.cookies
      : (() => {
          const setCookie = headers['set-cookie'];
          if (!setCookie) return [];
          const list = Array.isArray(setCookie) ? setCookie : [setCookie];
          return list.map(parseSetCookieHeader).filter(Boolean);
        })();

    for (const c of parsedCookies) {
      if (!c.httpOnly || !c.sameSite) {
        findings.push({
          severity: 'LOW',
          code: 'HTTP_WEAK_COOKIE_FLAGS',
          title: `Cookie "${c.name}" missing HttpOnly or SameSite attribute`,
          detail: `httpOnly=${c.httpOnly}, sameSite=${c.sameSite || 'none-set'}, secure=${c.secure}`,
        });
      }
      if (c.sameSite && c.sameSite.toLowerCase() === 'none' && !c.secure) {
        findings.push({
          severity: 'MEDIUM',
          code: 'HTTP_COOKIE_SAMESITE_NONE_INSECURE',
          title: `Cookie "${c.name}" uses SameSite=None without Secure`,
          detail: 'Browsers reject or downgrade SameSite=None cookies transmitted without the Secure flag.',
        });
      }
      if (c.domain && c.domain.startsWith('.')) {
        findings.push({
          severity: 'INFO',
          code: 'HTTP_COOKIE_BROAD_DOMAIN',
          title: `Cookie "${c.name}" scoped to wildcard domain "${c.domain}"`,
          detail: 'Subdomains can read or overwrite session/OAuth cookies scoped to a parent domain.',
        });
      }
    }
  }

  // 3. Token leakage in Location header
  if (context.location && /(#|&|\?)(access_token|id_token)=/i.test(context.location)) {
    findings.push({
      severity: 'HIGH',
      code: 'OAUTH_TOKEN_IN_REDIRECT',
      title: 'Token returned directly in Location redirect',
      detail: 'access_token or id_token is present in the redirect URI.',
    });
  }

  // 4. JWT extraction & audit
  const jwts = [
    ...extractAndInspectJwts(params),
    ...extractAndInspectJwts(context.location || ''),
    ...extractAndInspectJwts(context.responseBody || ''),
  ];

  const dedupedJwts = [];
  const seenTokens = new Set();
  for (const item of jwts) {
    if (seenTokens.has(item.token)) continue;
    seenTokens.add(item.token);
    dedupedJwts.push(item);
    for (const jf of item.inspection.findings || []) {
      findings.push(jf);
    }
  }

  return { findings, jwts: dedupedJwts };
}

function normalizeHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k.toLowerCase()] = v;
  }
  return out;
}
