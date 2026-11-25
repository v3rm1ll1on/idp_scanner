import crypto from 'node:crypto';
import { fetch as undiciFetch, Agent, ProxyAgent } from 'undici';
import { parseOAuthUrl } from './oauth/parser.js';
import { auditOAuthContext } from './oauth/analyzer.js';
import { parseSetCookieHeader } from './oauth/cookies.js';

/**
 * Builds an undici dispatcher for optional upstream HTTP(S) proxy and insecure TLS bypass.
 * @param {{insecureTls?: boolean, proxyUrl?: string}} [networkConfig]
 * @returns {Agent|ProxyAgent|undefined}
 */
export function createDispatcher(networkConfig = {}) {
  const { insecureTls = false, proxyUrl = '' } = networkConfig || {};
  if (proxyUrl) {
    return new ProxyAgent({
      uri: proxyUrl,
      requestTls: { rejectUnauthorized: !insecureTls },
      proxyTls: { rejectUnauthorized: !insecureTls },
    });
  }
  if (insecureTls) {
    return new Agent({
      connect: { rejectUnauthorized: false },
    });
  }
  return undefined;
}

/**
 * In-memory HTTP trace store with pub/sub notifications for SSE streaming.
 */
export class TraceStore {
  constructor(maxEntries = 200) {
    this.maxEntries = maxEntries;
    this.entries = [];
    this.listeners = new Set();
  }

  subscribe(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  notify(event, payload) {
    for (const fn of this.listeners) {
      try {
        fn(event, payload);
      } catch {
        // Ignore broken listener
      }
    }
  }

  add(entry) {
    this.entries.push(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.shift();
    }
    this.notify('trace', entry);
    return entry;
  }

  list() {
    return [...this.entries].reverse();
  }

  clear() {
    this.entries = [];
    this.notify('clear', {});
  }
}

/**
 * Evaluates whether a redirect_uri probe was accepted by the authorization endpoint.
 * @param {object} params
 * @returns {{accepted: boolean, verdict: string, hasCredential: boolean, hasError: boolean}}
 */
export function evaluateRedirectProbe({ status, location, mutatedUri, attackerHost }) {
  if (status < 300 || status >= 400 || !location) {
    return { accepted: false, verdict: 'BLOCKED', hasCredential: false, hasError: false };
  }

  const hasCredential = /([?&#])(code|access_token|id_token)=/i.test(location);
  const hasError = /([?&#])error=/i.test(location);

  let pointsToAttacker = false;
  if (attackerHost) {
    const cleanAttacker = attackerHost.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase();
    try {
      const locUrl = new URL(location);
      const locHost = locUrl.hostname.toLowerCase();
      pointsToAttacker = locHost === cleanAttacker || locHost.endsWith(`.${cleanAttacker}`);
    } catch {
      pointsToAttacker = false;
    }
  }

  const baseTarget = mutatedUri.split('?')[0].split('#')[0].toLowerCase();
  const matchesMutatedBase = location.toLowerCase().startsWith(baseTarget);

  if (hasCredential && !hasError) {
    return { accepted: true, verdict: 'ACCEPTED_WITH_CREDENTIAL', hasCredential, hasError };
  }
  if (!hasError && (pointsToAttacker || matchesMutatedBase)) {
    return { accepted: true, verdict: 'ACCEPTED_REDIRECT', hasCredential, hasError };
  }
  return { accepted: false, verdict: hasError ? 'REDIRECT_ERROR' : 'BLOCKED', hasCredential, hasError };
}

/**
 * Sends an HTTP request with manual redirect tracking so every hop is recorded.
 * @param {TraceStore} store
 * @param {object} options
 * @returns {Promise<Array<object>>}
 */
export async function sendAndTrace(store, options) {
  const {
    method = 'GET',
    url,
    headers = {},
    body = undefined,
    followRedirects = true,
    maxHops = 6,
    label = 'manual_request',
    cookieJar = null,
    networkConfig = null,
  } = options;

  const dispatcher = networkConfig ? createDispatcher(networkConfig) : undefined;

  const hops = [];
  let currentUrl = url;
  let currentMethod = method.toUpperCase();
  let currentBody = body;
  const traceGroupId = crypto.randomUUID();

  for (let hopIndex = 0; hopIndex < maxHops; hopIndex++) {
    const startedAt = Date.now();
    let parsedReq;
    try {
      parsedReq = parseOAuthUrl(currentUrl);
    } catch {
      parsedReq = { oauthParams: {}, flowKind: 'http_request', pathname: currentUrl };
    }

    const reqHeaders = { ...headers };
    delete reqHeaders.Host;
    delete reqHeaders.host;
    delete reqHeaders['Content-Length'];
    delete reqHeaders['content-length'];

    if (cookieJar && !reqHeaders.Cookie && !reqHeaders.cookie) {
      const jarHeader = cookieJar.getCookieHeader(currentUrl);
      if (jarHeader) {
        reqHeaders.Cookie = jarHeader;
      }
    }

    const fetchOptions = {
      method: currentMethod,
      headers: reqHeaders,
      redirect: 'manual',
      signal: AbortSignal.timeout(15000),
      ...(dispatcher ? { dispatcher } : {}),
    };
    if (currentBody && currentMethod !== 'GET' && currentMethod !== 'HEAD') {
      fetchOptions.body = currentBody;
    }

    const res = await undiciFetch(currentUrl, fetchOptions);
    const durationMs = Date.now() - startedAt;
    const responseText = await res.text();
    const responseHeaders = {};
    res.headers.forEach((val, key) => {
      responseHeaders[key] = val;
    });

    const rawSetCookies =
      typeof res.headers.getSetCookie === 'function'
        ? res.headers.getSetCookie()
        : responseHeaders['set-cookie']
          ? [responseHeaders['set-cookie']]
          : [];
    if (rawSetCookies.length > 0) {
      responseHeaders['set-cookie'] = rawSetCookies.length === 1 ? rawSetCookies[0] : rawSetCookies;
      if (cookieJar) {
        cookieJar.setFromHeaders(currentUrl, rawSetCookies);
      }
    }
    const parsedCookies = rawSetCookies.map(parseSetCookieHeader).filter(Boolean);

    const location = responseHeaders.location || null;
    let resolvedLocation = null;
    let parsedLocation = null;
    if (location) {
      try {
        resolvedLocation = new URL(location, currentUrl).toString();
        parsedLocation = parseOAuthUrl(resolvedLocation);
      } catch {
        resolvedLocation = null;
        parsedLocation = null;
      }
    }

    const audit = auditOAuthContext({
      oauthParams: {
        ...parsedReq.oauthParams,
        ...(parsedLocation ? parsedLocation.oauthParams : {}),
      },
      requestHeaders: reqHeaders,
      requestBody: currentBody || '',
      responseHeaders,
      cookies: parsedCookies,
      status: res.status,
      location: resolvedLocation || location,
      responseBody: responseText,
    });

    const entry = store.add({
      id: crypto.randomUUID(),
      traceGroupId,
      hopIndex,
      timestamp: new Date().toISOString(),
      label,
      flowKind: parsedLocation?.flowKind || parsedReq.flowKind,
      durationMs,
      request: {
        method: currentMethod,
        url: currentUrl,
        headers: reqHeaders,
        body: currentBody || '',
        oauthParams: parsedReq.oauthParams,
      },
      response: {
        status: res.status,
        statusText: res.statusText,
        headers: responseHeaders,
        cookies: parsedCookies,
        location,
        body: responseText,
        oauthParams: parsedLocation?.oauthParams || {},
      },
      audit,
    });

    hops.push(entry);

    if (!followRedirects || !resolvedLocation || !/^https?:\/\//i.test(resolvedLocation) || res.status < 300 || res.status >= 400) {
      break;
    }

    currentUrl = resolvedLocation;
    if (res.status === 301 || res.status === 302 || res.status === 303) {
      currentMethod = 'GET';
      currentBody = undefined;
    }
  }

  return hops;
}

/**
 * Replaces or appends redirect_uri without double-encoding existing %XX sequences.
 * When isHpp is true, preserves an unescaped "&redirect_uri=" separator for HTTP Parameter Pollution probes.
 * @param {string} baseUrl
 * @param {string} rawRedirectUri
 * @param {{isHpp?: boolean}} [options]
 * @returns {string}
 */
export function buildUrlWithRawRedirectUri(baseUrl, rawRedirectUri, { isHpp = false } = {}) {
  const urlObj = new URL(baseUrl);
  urlObj.searchParams.delete('redirect_uri');
  const base = urlObj.toString();
  const sep = base.includes('?') ? (base.endsWith('?') || base.endsWith('&') ? '' : '&') : '?';
  let safeVal = String(rawRedirectUri)
    .replace(/#/g, '%23')
    .replace(/ /g, '%20');
  if (!isHpp) {
    safeVal = safeVal.replace(/&/g, '%26');
  }
  return `${base}${sep}redirect_uri=${safeVal}`;
}

/**
 * Tests a batch of redirect_uri mutations against an authorization URL without following redirects.
 * @param {TraceStore} store
 * @param {object} options
 * @returns {Promise<Array<object>>}
 */
export async function batchTestRedirectUris(
  store,
  { baseUrl, headers = {}, mutations = [], attackerHost = 'attacker.example', cookieJar = null, networkConfig = null }
) {
  const results = [];

  for (const mut of mutations) {
    const targetUrl = buildUrlWithRawRedirectUri(baseUrl, mut.uri, { isHpp: Boolean(mut.isHpp) });

    try {
      const hops = await sendAndTrace(store, {
        method: 'GET',
        url: targetUrl,
        headers,
        followRedirects: false,
        maxHops: 1,
        cookieJar,
        networkConfig,
        label: `redirect_probe:${mut.id}`,
      });

      const hop = hops[0];
      const status = hop.response.status;
      const location = hop.response.location || '';
      const evaluation = evaluateRedirectProbe({
        status,
        location,
        mutatedUri: mut.uri,
        attackerHost,
      });

      results.push({
        id: mut.id,
        category: mut.category,
        label: mut.label,
        testedUri: mut.uri,
        status,
        location,
        accepted: evaluation.accepted,
        verdict: evaluation.verdict,
        traceId: hop.id,
      });
    } catch (err) {
      results.push({
        id: mut.id,
        category: mut.category,
        label: mut.label,
        testedUri: mut.uri,
        status: 0,
        location: '',
        accepted: false,
        verdict: 'ERROR',
        error: err.message,
      });
    }
  }

  return results;
}

/**
 * Tests a batch of OAuth parameter mutations (state, response_type, PKCE, scope, prompt) against an authorize URL.
 * @param {TraceStore} store
 * @param {object} options
 * @returns {Promise<Array<object>>}
 */
export async function batchTestOAuthParams(
  store,
  { baseUrl, headers = {}, mutations = [], cookieJar = null, networkConfig = null }
) {
  const results = [];

  for (const mut of mutations) {
    const targetUrl = new URL(baseUrl);
    for (const [k, v] of Object.entries(mut.patch || {})) {
      if (k === 'scope_append') {
        const cur = targetUrl.searchParams.get('scope') || 'openid';
        targetUrl.searchParams.set('scope', `${cur} ${v}`.trim());
      } else if (v === null) {
        targetUrl.searchParams.delete(k);
      } else {
        targetUrl.searchParams.set(k, v);
      }
    }

    try {
      const hops = await sendAndTrace(store, {
        method: 'GET',
        url: targetUrl.toString(),
        headers,
        followRedirects: false,
        maxHops: 1,
        cookieJar,
        networkConfig,
        label: `param_probe:${mut.id}`,
      });

      const hop = hops[0];
      const status = hop.response.status;
      const location = hop.response.location || '';
      const hasError = /([?&#])error=/i.test(location);
      const accepted = status >= 300 && status < 400 && !hasError;

      results.push({
        id: mut.id,
        label: mut.label,
        description: mut.description,
        testedUrl: targetUrl.toString(),
        status,
        location,
        accepted,
        verdict: accepted ? 'ACCEPTED (RISK)' : hasError ? 'REDIRECT_ERROR' : 'BLOCKED',
        traceId: hop.id,
      });
    } catch (err) {
      results.push({
        id: mut.id,
        label: mut.label,
        description: mut.description,
        testedUrl: targetUrl.toString(),
        status: 0,
        location: '',
        accepted: false,
        verdict: 'ERROR',
        error: err.message,
      });
    }
  }

  return results;
}

/**
 * Fuzzes a single query or body parameter against a baseline response to detect status/location/length anomalies.
 * @param {TraceStore} store
 * @param {object} options
 * @returns {Promise<{baseline: object, results: Array<object>}>}
 */
export async function batchTestCustomField(
  store,
  {
    method = 'GET',
    baseUrl,
    headers = {},
    body = '',
    targetLocation = 'query',
    paramName,
    payloads = [],
    cookieJar = null,
    networkConfig = null,
  }
) {
  let baselineHops;
  try {
    baselineHops = await sendAndTrace(store, {
      method,
      url: baseUrl,
      headers,
      body,
      followRedirects: false,
      maxHops: 1,
      cookieJar,
      networkConfig,
      label: `custom_baseline:${paramName}`,
    });
  } catch (err) {
    throw new Error(`Baseline request failed: ${err.message}`);
  }

  const baseHop = baselineHops[0];
  const baseStatus = baseHop.response.status;
  const baseLocation = baseHop.response.location || '';
  const baseLen = (baseHop.response.body || '').length;

  const results = [];
  for (const payload of payloads) {
    let reqUrl = baseUrl;
    let reqBody = body;

    if (targetLocation === 'body') {
      const ct = (headers['Content-Type'] || headers['content-type'] || '').toLowerCase();
      if (ct.includes('application/json')) {
        try {
          const obj = JSON.parse(body || '{}');
          obj[paramName] = payload;
          reqBody = JSON.stringify(obj);
        } catch {
          reqBody = body;
        }
      } else {
        const params = new URLSearchParams(body || '');
        params.set(paramName, payload);
        reqBody = params.toString();
      }
    } else {
      const u = new URL(baseUrl);
      u.searchParams.set(paramName, payload);
      reqUrl = u.toString();
    }

    try {
      const hops = await sendAndTrace(store, {
        method,
        url: reqUrl,
        headers,
        body: reqBody,
        followRedirects: false,
        maxHops: 1,
        cookieJar,
        networkConfig,
        label: `custom_probe:${paramName}`,
      });
      const hop = hops[0];
      const status = hop.response.status;
      const location = hop.response.location || '';
      const bodyLen = (hop.response.body || '').length;
      const lenDelta = bodyLen - baseLen;
      const anomaly = status !== baseStatus || location !== baseLocation || lenDelta !== 0;

      results.push({
        payload,
        status,
        location,
        bodyLen,
        lenDelta,
        anomaly,
        verdict: anomaly ? 'ANOMALY' : 'SAME',
        traceId: hop.id,
      });
    } catch (err) {
      results.push({
        payload,
        status: 0,
        location: '',
        bodyLen: 0,
        lenDelta: 0,
        anomaly: true,
        verdict: 'ERROR',
        error: err.message,
      });
    }
  }

  return {
    baseline: { status: baseStatus, location: baseLocation, bodyLen: baseLen },
    results,
  };
}

/**
 * Tests a batch of Token Endpoint (/token) mutations against a POST /token request.
 * @param {TraceStore} store
 * @param {object} options
 * @returns {Promise<Array<object>>}
 */
export async function batchTestTokenEndpoint(
  store,
  { url, headers = {}, body = '', mutations = [], attackerHost = 'attacker.example', cookieJar = null, networkConfig = null }
) {
  const results = [];
  const reqHeaders = { ...headers };
  delete reqHeaders['content-type'];
  delete reqHeaders['Content-Type'];
  reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';

  for (const mut of mutations) {
    const params = new URLSearchParams(body || '');
    if (mut.id === 'TOKEN_STRIP_VERIFIER') params.delete('code_verifier');
    else if (mut.id === 'TOKEN_WRONG_VERIFIER') params.set('code_verifier', 'invalid_pkce_verifier_probe');
    else if (mut.id === 'TOKEN_MISMATCH_REDIRECT') params.set('redirect_uri', `https://${attackerHost}/callback`);
    else if (mut.id === 'TOKEN_DROP_REDIRECT') params.delete('redirect_uri');
    else if (mut.id === 'TOKEN_DROP_CLIENT_SECRET') params.delete('client_secret');

    try {
      const hops = await sendAndTrace(store, {
        method: 'POST',
        url,
        headers: reqHeaders,
        body: params.toString(),
        followRedirects: false,
        maxHops: 1,
        cookieJar,
        networkConfig,
        label: `token_probe:${mut.id}`,
      });

      let hop = hops[0];
      if (mut.id === 'TOKEN_REPLAY_CODE') {
        const secondHops = await sendAndTrace(store, {
          method: 'POST',
          url,
          headers: reqHeaders,
          body: params.toString(),
          followRedirects: false,
          maxHops: 1,
          cookieJar,
          networkConfig,
          label: `token_probe:${mut.id}_2nd`,
        });
        hop = secondHops[0];
      }

      const status = hop.response.status;
      const accepted = status >= 200 && status < 300 && /access_token|id_token/i.test(hop.response.body || '');

      results.push({
        id: mut.id,
        label: mut.label,
        description: mut.description,
        status,
        accepted,
        verdict: accepted ? 'ACCEPTED (RISK)' : 'BLOCKED',
        traceId: hop.id,
      });
    } catch (err) {
      results.push({
        id: mut.id,
        label: mut.label,
        description: mut.description,
        status: 0,
        accepted: false,
        verdict: 'ERROR',
        error: err.message,
      });
    }
  }

  return results;
}
