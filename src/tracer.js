import crypto from 'node:crypto';
import { parseOAuthUrl } from './oauth/parser.js';
import { auditOAuthContext } from './oauth/analyzer.js';

/**
 * In-memory HTTP trace store and OAuth request/replay engine.
 */
export class TraceStore {
  constructor(maxEntries = 200) {
    this.maxEntries = maxEntries;
    this.entries = [];
  }

  add(entry) {
    this.entries.push(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.shift();
    }
    return entry;
  }

  list() {
    return [...this.entries].reverse();
  }

  clear() {
    this.entries = [];
  }
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
    // Remove hop-specific Host header so Node fetch sets it accurately
    delete reqHeaders.Host;
    delete reqHeaders.host;
    delete reqHeaders['Content-Length'];
    delete reqHeaders['content-length'];

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
 * Tests a batch of redirect_uri mutations against an authorization URL without following redirects.
 * @param {TraceStore} store
 * @param {object} options
 * @returns {Promise<Array<object>>}
 */
export async function batchTestRedirectUris(store, { baseUrl, headers = {}, mutations = [] }) {
  const results = [];

  for (const mut of mutations) {
    const targetUrl = new URL(baseUrl);
    targetUrl.searchParams.set('redirect_uri', mut.uri);

    try {
      const hops = await sendAndTrace(store, {
        method: 'GET',
        url: targetUrl.toString(),
        headers,
        followRedirects: false,
        maxHops: 1,
        label: `redirect_probe:${mut.id}`,
      });

      const hop = hops[0];
      const status = hop.response.status;
      const location = hop.response.location || '';
      const accepted = status >= 300 && status < 400 && location.includes(mut.uri.split('?')[0].split('#')[0]);

      results.push({
        id: mut.id,
        category: mut.category,
        label: mut.label,
        testedUri: mut.uri,
        status,
        location,
        accepted,
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
        error: err.message,
      });
    }
  }

  return results;
}
