/**
 * Parses a single Set-Cookie header string into structured attributes.
 * @param {string} raw
 * @returns {object|null}
 */
export function parseSetCookieHeader(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const parts = raw.split(';').map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0) return null;

  const eqIdx = parts[0].indexOf('=');
  if (eqIdx <= 0) return null;

  const name = parts[0].slice(0, eqIdx).trim();
  const value = parts[0].slice(eqIdx + 1).trim();

  const cookie = {
    name,
    value,
    domain: null,
    path: '/',
    expires: null,
    maxAge: null,
    httpOnly: false,
    secure: false,
    sameSite: null,
  };

  for (let i = 1; i < parts.length; i++) {
    const attr = parts[i];
    const attrEq = attr.indexOf('=');
    const key = (attrEq === -1 ? attr : attr.slice(0, attrEq)).trim().toLowerCase();
    const val = attrEq === -1 ? '' : attr.slice(attrEq + 1).trim();

    if (key === 'domain') cookie.domain = val.toLowerCase();
    else if (key === 'path') cookie.path = val || '/';
    else if (key === 'expires') cookie.expires = val;
    else if (key === 'max-age') cookie.maxAge = Number.isFinite(Number(val)) ? Number(val) : null;
    else if (key === 'httponly') cookie.httpOnly = true;
    else if (key === 'secure') cookie.secure = true;
    else if (key === 'samesite') cookie.sameSite = val || 'Lax';
  }

  return cookie;
}

/**
 * In-memory session CookieJar for multi-hop OAuth tracing and repeater flows.
 */
export class CookieJar {
  constructor() {
    this.cookies = new Map();
  }

  /**
   * Stores parsed Set-Cookie headers scoped to the responding URL.
   * @param {string} requestUrl
   * @param {Array<string>} setCookieHeaders
   */
  setFromHeaders(requestUrl, setCookieHeaders = []) {
    let urlObj;
    try {
      urlObj = new URL(requestUrl);
    } catch {
      return;
    }

    for (const raw of setCookieHeaders) {
      const parsed = parseSetCookieHeader(raw);
      if (!parsed) continue;

      const host = urlObj.hostname.toLowerCase();
      const domain = parsed.domain ? parsed.domain.replace(/^\./, '') : host;
      if (parsed.domain && host !== domain && !host.endsWith(`.${domain}`)) {
        continue;
      }
      const hostOnly = !parsed.domain;
      const key = `${domain}|${parsed.path}|${parsed.name}`;

      if (parsed.maxAge !== null && parsed.maxAge <= 0) {
        this.cookies.delete(key);
        continue;
      }
      if (parsed.maxAge === null && parsed.expires) {
        const expMs = Date.parse(parsed.expires);
        if (!Number.isNaN(expMs) && expMs <= Date.now()) {
          this.cookies.delete(key);
          continue;
        }
      }

      this.cookies.set(key, {
        ...parsed,
        domain,
        hostOnly,
        setAt: new Date().toISOString(),
      });
    }
  }

  /**
   * Returns a Cookie header string matching the target URL, or null if none match.
   * @param {string} targetUrl
   * @returns {string|null}
   */
  getCookieHeader(targetUrl) {
    let urlObj;
    try {
      urlObj = new URL(targetUrl);
    } catch {
      return null;
    }

    const host = urlObj.hostname.toLowerCase();
    const path = urlObj.pathname || '/';
    const isHttps = urlObj.protocol === 'https:';
    const isLoopback = host === 'localhost' || host === '127.0.0.1' || host === '[::1]';

    const matched = [];
    for (const c of this.cookies.values()) {
      const domainMatch = c.hostOnly
        ? host === c.domain
        : host === c.domain || host.endsWith(`.${c.domain}`);
      if (!domainMatch) continue;
      const pathMatch =
        path === c.path ||
        (c.path.endsWith('/') ? path.startsWith(c.path) : path.startsWith(`${c.path}/`));
      if (!pathMatch) continue;
      if (c.secure && !isHttps && !isLoopback) continue;
      matched.push(`${c.name}=${c.value}`);
    }

    return matched.length > 0 ? matched.join('; ') : null;
  }

  list() {
    return [...this.cookies.values()];
  }

  clear() {
    this.cookies.clear();
  }
}
