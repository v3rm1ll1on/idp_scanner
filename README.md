# OAuth Workbench (`idp_scanner`)

Analytical OAuth 2.0 / OIDC Flow Visualizer, HTTP Trace Inspector, and Security Audit Workbench built with Node.js (v22) and Express.

## Features

- **HTTP Trace & Manual Redirect Tracker:** Logs every HTTP hop (`302 Location`, request/response headers, body, timing) without swallowing redirects. Live-updated via Server-Sent Events (`/api/traces/stream`).
- **Synchronized Sequence Visualizer:** Interactive SVG sequence diagram (`Client` ↔ `Authorization Server` ↔ `Callback` ↔ `Token / Resource`); clicking any arrow selects the corresponding HTTP trace.
- **Request Parser & Repeater:** Paste an Authorization URL or a raw HTTP request (e.g. from Burp Suite) to parse parameters, generate PKCE (`S256`) / `state` / `nonce`, mutate OAuth parameters (`state`, `response_type`, `PKCE`, `scope`), and replay requests with baseline diffing.
- **`redirect_uri` Mutation Matrix (19 Payloads):** Built-in enumeration of `redirect_uri` bypass patterns (subdomain suffix/prefix, `@` and `%40` authority confusion, backslash confusion, path traversal, scheme downgrade, loopback variants, CRLF/null-byte/double-encoding) with single-click load or automated batch probing.
- **JWT & Security Auditor:** Decodes JWTs (`id_token`, `access_token`) and flags `alg: none`, missing `exp`/`aud`, missing `state`, Implicit flow usage, missing/plain PKCE, and weak HTTP security headers (`Cache-Control: no-store`, `Referrer-Policy`, `Set-Cookie` flags).
- **Local Callback Listener & Configurable Mock IdP:** Built-in `/callback` endpoint (captures both query parameters and `#fragment` tokens) plus a toggleable `/mock-idp` sandbox for testing misconfigurations safely.

## Quick Start

```bash
npm install
npm start
```

Open `http://localhost:3000` in your browser and click **Run Demo Flow** or **Discover**.

## Running Tests

```bash
npm test
```
