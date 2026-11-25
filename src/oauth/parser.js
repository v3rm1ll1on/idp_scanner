/**
 * Parses an OAuth/OIDC URL (including query and fragment parameters).
 * @param {string} rawUrl
 * @returns {object}
 */
export function parseOAuthUrl(rawUrl) {
  const url = new URL(rawUrl.trim());
  const queryParams = Object.fromEntries(url.searchParams.entries());
  const fragmentStr = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash;
  const fragmentParams = fragmentStr ? Object.fromEntries(new URLSearchParams(fragmentStr).entries()) : {};

  const combined = { ...queryParams, ...fragmentParams };
  const flowKind = inferFlowKind(url.pathname, combined);

  return {
    url: url.toString(),
    origin: url.origin,
    pathname: url.pathname,
    baseUrl: `${url.origin}${url.pathname}`,
    queryParams,
    fragmentParams,
    oauthParams: pickOAuthParams(combined),
    flowKind,
  };
}

/**
 * Parses a raw HTTP request (e.g. copied from Burp Suite) into method, URL, headers, and body.
 * @param {string} rawRequest
 * @param {string} [defaultScheme='https']
 * @returns {object}
 */
export function parseRawHttpRequest(rawRequest, defaultScheme = 'https') {
  const normalized = rawRequest.replace(/\r\n/g, '\n').trim();
  const splitIdx = normalized.indexOf('\n\n');
  const headSection = splitIdx === -1 ? normalized : normalized.slice(0, splitIdx);
  const body = splitIdx === -1 ? '' : normalized.slice(splitIdx + 2);

  const lines = headSection.split('\n').filter(Boolean);
  if (lines.length === 0) {
    throw new Error('Empty raw HTTP request');
  }

  const requestLineParts = lines[0].trim().split(/\s+/);
  if (requestLineParts.length < 2) {
    throw new Error(`Invalid HTTP request line: "${lines[0]}"`);
  }

  const method = requestLineParts[0].toUpperCase();
  const target = requestLineParts[1];
  const headers = {};

  for (let i = 1; i < lines.length; i++) {
    const colonIdx = lines[i].indexOf(':');
    if (colonIdx === -1) continue;
    const name = lines[i].slice(0, colonIdx).trim();
    const value = lines[i].slice(colonIdx + 1).trim();
    if (name.toLowerCase() === 'cookie' && headers[name]) {
      headers[name] = `${headers[name]}; ${value}`;
    } else {
      headers[name] = value;
    }
  }

  let fullUrl;
  if (/^https?:\/\//i.test(target)) {
    fullUrl = target;
  } else {
    const hostHeader = headers.Host || headers.host;
    if (!hostHeader) {
      throw new Error('Relative request path requires a Host header');
    }
    const scheme = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i.test(hostHeader) ? 'http' : defaultScheme;
    fullUrl = `${scheme}://${hostHeader}${target.startsWith('/') ? '' : '/'}${target}`;
  }

  const parsedUrl = parseOAuthUrl(fullUrl);
  let bodyParams = {};
  const contentType = (headers['Content-Type'] || headers['content-type'] || '').toLowerCase();
  if (body && contentType.includes('application/x-www-form-urlencoded')) {
    bodyParams = Object.fromEntries(new URLSearchParams(body).entries());
  } else if (body && contentType.includes('application/json')) {
    try {
      bodyParams = JSON.parse(body);
    } catch {
      bodyParams = {};
    }
  }

  const combined = { ...parsedUrl.queryParams, ...parsedUrl.fragmentParams, ...bodyParams };

  return {
    method,
    url: parsedUrl.url,
    baseUrl: parsedUrl.baseUrl,
    headers,
    body,
    queryParams: parsedUrl.queryParams,
    fragmentParams: parsedUrl.fragmentParams,
    bodyParams,
    oauthParams: pickOAuthParams(combined),
    flowKind: inferFlowKind(parsedUrl.pathname, combined),
  };
}

/**
 * Summarizes an OIDC / OAuth2 discovery document.
 * @param {object} doc
 * @returns {object}
 */
export function summarizeDiscovery(doc) {
  return {
    issuer: doc.issuer || null,
    authorization_endpoint: doc.authorization_endpoint || null,
    token_endpoint: doc.token_endpoint || null,
    userinfo_endpoint: doc.userinfo_endpoint || null,
    jwks_uri: doc.jwks_uri || null,
    end_session_endpoint: doc.end_session_endpoint || null,
    revocation_endpoint: doc.revocation_endpoint || null,
    introspection_endpoint: doc.introspection_endpoint || null,
    response_types_supported: doc.response_types_supported || [],
    grant_types_supported: doc.grant_types_supported || [],
    scopes_supported: doc.scopes_supported || [],
    code_challenge_methods_supported: doc.code_challenge_methods_supported || [],
    token_endpoint_auth_methods_supported: doc.token_endpoint_auth_methods_supported || [],
  };
}

function pickOAuthParams(params) {
  const keys = [
    'client_id',
    'client_secret',
    'redirect_uri',
    'response_type',
    'response_mode',
    'scope',
    'state',
    'nonce',
    'code_challenge',
    'code_challenge_method',
    'code_verifier',
    'code',
    'grant_type',
    'access_token',
    'id_token',
    'refresh_token',
    'token_type',
    'expires_in',
    'error',
    'error_description',
    'prompt',
    'acr_values',
  ];
  const result = {};
  for (const key of keys) {
    if (params[key] !== undefined) {
      result[key] = params[key];
    }
  }
  return result;
}

function inferFlowKind(pathname, params) {
  if (params.error) return 'error_response';
  if (params.access_token || params.id_token) {
    return params.code ? 'hybrid_callback' : 'implicit_callback';
  }
  if (params.code && !params.response_type) return 'authorization_code_callback';
  if (params.grant_type) return `token_exchange:${params.grant_type}`;
  if (params.response_type) {
    const rt = params.response_type.trim();
    if (rt === 'code') return 'authorization_code_request';
    if (rt.includes('token') && rt.includes('code')) return 'hybrid_request';
    if (rt.includes('token')) return 'implicit_request';
    return `authorize:${rt}`;
  }
  if (/userinfo/i.test(pathname)) return 'userinfo_request';
  if (/token/i.test(pathname)) return 'token_request';
  if (/authorize/i.test(pathname)) return 'authorize_request';
  return 'http_request';
}
