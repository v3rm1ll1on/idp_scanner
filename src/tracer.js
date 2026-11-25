import crypto from 'node:crypto';
import { parseOAuthUrl } from './oauth/parser.js';
import { auditOAuthContext } from './oauth/analyzer.js';
import { parseSetCookieHeader } from './oauth/cookies.js';

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
    const cleanAttacker = attackerHost.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
    try {
      const locUrl = new URL(location);
      pointsToAttacker = locUrl.hostname.toLowerCase().includes(cleanAttacker);
    } catch {
      pointsToAttacker = location.toLowerCase().includes(cleanAttacker);
    }
  }

  const baseTarget = mutatedUri.split('?')[0].split('#')[0].toLowerCase();
  const matchesMutatedBase = location.toLowerCase().startsWith(baseTarget);

  if (hasCredential && !hasError && (pointsToAttacker || matchesMutatedBase)) {
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
  } = options;

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
    };
    if (currentBody && currentMethod !== 'GET' && currentMethod !== 'HEAD') {
      fetchOptions.body = currentBody;
    }

    const res = await fetch(currentUrl, fetchOptions);
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
    let parsedLocation = null;
    if (location) {
      try {
        const resolved = new URL(location, currentUrl).toString();
        parsedLocation = parseOAuthUrl(resolved);
      } catch {
        parsedLocation = null;
      }
    }

    const audit = auditOAuthContext({
      oauthParams: {
        ...parsedReq.oauthParams,
        ...(parsedLocation ? parsedLocation.oauthParams : {}),
      },
      responseHeaders,
      cookies: parsedCookies,
      status: res.status,
      location: location ? new URL(location, currentUrl).toString() : null,
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

    if (!followRedirects || !location || res.status < 300 || res.status >= 400) {
      break;
    }

    currentUrl = new URL(location, currentUrl).toString();
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
  { baseUrl, headers = {}, mutations = [], attackerHost = 'attacker.example', cookieJar = null }
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
