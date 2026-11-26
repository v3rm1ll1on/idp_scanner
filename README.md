# OAuth Workbench (`idp_scanner`)

Analytical OAuth 2.0 / OIDC Flow Visualizer, HTTP Trace Inspector, and Security Audit Workbench built with Node.js (v22) and Express.

## Features

- **HTTP Trace & Manual Redirect Tracker:** Logs every HTTP hop (`302 Location`, request/response headers, body, timing) without swallowing redirects. Live-updated via Server-Sent Events (`/api/traces/stream`).
- **Synchronized Sequence Visualizer:** Interactive SVG sequence diagram (`Client` ↔ `Authorization Server` ↔ `Callback` ↔ `Token / Resource`); clicking any arrow selects the corresponding HTTP trace.
- **Request Parser & Repeater:** Paste an Authorization URL or a raw HTTP request (e.g. from Burp Suite) to parse parameters, generate PKCE (`S256`) / `state` / `nonce`, mutate OAuth parameters (`state`, `response_type`, `PKCE`, `scope`), and replay requests with baseline diffing.
- **`redirect_uri` Mutation Matrix (28 Payloads):** Built-in enumeration of `redirect_uri` bypass patterns (subdomain suffix/prefix, `@` and `%40` authority confusion, backslash confusion, path traversal, matrix/semicolon, HPP duplicate `redirect_uri`, scheme downgrade, custom mobile scheme, IPv4 decimal/hex/short/loopback variants, CRLF/null-byte/tab/Unicode/double-encoding) with single-click load or automated batch probing.
- **JWT & Security Auditor:** Decodes JWTs (`id_token`, `access_token`) and flags `alg: none`, missing `exp`/`aud`, missing `state`, Implicit flow usage, missing/plain PKCE, and weak HTTP security headers (`Cache-Control: no-store`, `Referrer-Policy`, `Set-Cookie` flags).
- **Local Callback Listener & Configurable Mock IdP:** Built-in `/callback` endpoint (captures both query parameters and `#fragment` tokens) plus a toggleable `/mock-idp` sandbox for testing misconfigurations safely.

## Quick Start

```bash
npm install
npm start
```

### Offline / Behind Proxy (GitHub Release)

Download `oauth-workbench-<version>.tar.gz` (or `.zip`) from **GitHub Releases** — it already includes production `node_modules/`, so no `npm install` is needed:

```bash
tar -xzf oauth-workbench-v1.0.0.tar.gz
cd oauth-workbench
node src/server.js
```

Open `http://127.0.0.1:3000` in your browser (or `http://127.0.0.1:3000/?demo=true` for the built-in Mock IdP sandbox).

### HTTPS / HSTS Listener

Start an additional HTTPS listener (auto-generates a self-signed SAN cert, or pass your own `SSL_CERT`/`SSL_KEY` e.g. from `mkcert`):

```bash
HTTPS=true HTTPS_PORT=3443 SSL_DOMAINS=localhost,attacker.example node src/server.js
# Or with port 443 + custom cert:
sudo HTTPS_PORT=443 SSL_CERT=./cert.pem SSL_KEY=./key.pem node src/server.js
```

## Running Tests

```bash
npm test
```
