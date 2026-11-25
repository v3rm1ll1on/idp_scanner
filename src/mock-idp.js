import crypto from 'node:crypto';
import express from 'express';
import { encodeBase64Url } from './oauth/jwt.js';

/**
 * Creates a configurable local Mock OIDC/OAuth2 Identity Provider for testing.
 * @param {object} [initialConfig]
 * @returns {{router: express.Router, getConfig: function, setConfig: function}}
 */
export function createMockIdp(initialConfig = {}) {
  const router = express.Router();
  const codes = new Map();
  const tokens = new Map();

  const config = {
    allowOpenRedirect: false,
    allowMissingState: true,
    allowImplicitDowngrade: true,
    allowPkceDowngrade: true,
    allowAlgNone: false,
    allowedRedirectPrefix: 'http://localhost:',
    ...initialConfig,
  };

  const hmacSecret = 'mock-idp-dev-secret-do-not-use-in-prod';

  function signJwt(payload, useAlgNone = false) {
    const header = {
      alg: useAlgNone ? 'none' : 'HS256',
      typ: 'JWT',
      kid: 'mock-key-1',
    };
    const encodedHeader = encodeBase64Url(header);
    const encodedPayload = encodeBase64Url(payload);
    if (useAlgNone) {
      return `${encodedHeader}.${encodedPayload}.`;
    }
    const sig = crypto
      .createHmac('sha256', hmacSecret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    return `${encodedHeader}.${encodedPayload}.${sig}`;
  }

  function getBaseUrl(req) {
    return `${req.protocol}://${req.get('host')}${req.baseUrl}`;
  }

  function isRedirectAllowed(redirectUri) {
    if (!redirectUri) return false;
    if (config.allowOpenRedirect) return true;
    try {
      const parsed = new URL(redirectUri);
      const allowed = new URL(
        config.allowedRedirectPrefix.endsWith(':')
          ? `${config.allowedRedirectPrefix}3000`
          : config.allowedRedirectPrefix
      );
      return parsed.protocol === allowed.protocol && parsed.hostname === allowed.hostname;
    } catch {
      return false;
    }
  }

  router.get('/config', (_req, res) => {
    res.json(config);
  });

  router.post('/config', express.json(), (req, res) => {
    Object.assign(config, req.body || {});
    res.json(config);
  });

  router.get('/.well-known/openid-configuration', (req, res) => {
    const base = getBaseUrl(req);
    res.json({
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      userinfo_endpoint: `${base}/userinfo`,
      jwks_uri: `${base}/jwks.json`,
      response_types_supported: config.allowImplicitDowngrade
        ? ['code', 'token', 'id_token', 'code id_token']
        : ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      scopes_supported: ['openid', 'profile', 'email', 'admin', 'offline_access'],
      code_challenge_methods_supported: config.allowPkceDowngrade ? ['S256', 'plain'] : ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    });
  });

  router.get('/jwks.json', (_req, res) => {
    res.json({
      keys: [
        {
          kty: 'oct',
          kid: 'mock-key-1',
          use: 'sig',
          alg: 'HS256',
        },
      ],
    });
  });

  router.get('/authorize', (req, res) => {
    const {
      client_id,
      redirect_uri: rawRedirectUri,
      response_type = 'code',
      scope = 'openid profile',
      state,
      nonce,
      code_challenge,
      code_challenge_method,
    } = req.query;

    const redirect_uri = Array.isArray(rawRedirectUri)
      ? rawRedirectUri[rawRedirectUri.length - 1]
      : rawRedirectUri;

    if (!client_id) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Missing client_id' });
    }

    if (!isRedirectAllowed(redirect_uri)) {
      return res.status(400).json({
        error: 'invalid_redirect_uri',
        error_description: `redirect_uri "${redirect_uri || ''}" is not permitted`,
      });
    }

    let target;
    try {
      target = new URL(redirect_uri);
    } catch {
      return res.status(400).json({
        error: 'invalid_redirect_uri',
        error_description: `Malformed redirect_uri "${redirect_uri || ''}"`,
      });
    }

    if (!config.allowMissingState && !state) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'state parameter required' });
    }

    const rtParts = String(response_type).split(/\s+/);
    if ((rtParts.includes('token') || rtParts.includes('id_token')) && !config.allowImplicitDowngrade) {
      return res.status(400).json({
        error: 'unsupported_response_type',
        error_description: 'Implicit/hybrid flows are disabled',
      });
    }

    if (code_challenge && code_challenge_method === 'plain' && !config.allowPkceDowngrade) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'PKCE plain method is not allowed',
      });
    }

    // Simulate authenticated session cookie (intentionally weak flags if testing)
    res.setHeader('Set-Cookie', 'mock_idp_session=sess_demo_123; Path=/');

    if (rtParts.includes('token') || rtParts.includes('id_token')) {
      const now = Math.floor(Date.now() / 1000);
      const frag = new URLSearchParams();
      if (rtParts.includes('token')) {
        const accessToken = signJwt(
          { sub: 'pentester-demo', scope, client_id, iss: getBaseUrl(req), iat: now, exp: now + 3600 },
          config.allowAlgNone
        );
        tokens.set(accessToken, { sub: 'pentester-demo', scope, email: 'pentester@mock.local' });
        frag.set('access_token', accessToken);
        frag.set('token_type', 'Bearer');
        frag.set('expires_in', '3600');
      }
      if (rtParts.includes('id_token')) {
        const idToken = signJwt(
          {
            sub: 'pentester-demo',
            aud: client_id,
            iss: getBaseUrl(req),
            nonce: nonce || undefined,
            email: 'pentester@mock.local',
            iat: now,
            exp: now + 3600,
          },
          config.allowAlgNone
        );
        frag.set('id_token', idToken);
      }
      if (state) frag.set('state', state);
      target.hash = frag.toString();
      return res.redirect(302, target.toString());
    }

    // Authorization code flow
    const code = `mock_code_${crypto.randomBytes(6).toString('hex')}`;
    codes.set(code, {
      client_id,
      redirect_uri,
      scope,
      nonce,
      code_challenge,
      code_challenge_method: code_challenge_method || 'plain',
      createdAt: Date.now(),
    });

    target.searchParams.set('code', code);
    if (state) target.searchParams.set('state', state);
    return res.redirect(302, target.toString());
  });

  router.post('/token', express.urlencoded({ extended: false }), express.json(), (req, res) => {
    const { grant_type, code, redirect_uri, client_id = 'demo-client', code_verifier } = req.body || {};

    if (grant_type !== 'authorization_code') {
      return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    const record = codes.get(code);
    if (!record) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Unknown or expired code' });
    }
    codes.delete(code);

    if (record.redirect_uri && redirect_uri && record.redirect_uri !== redirect_uri && !config.allowOpenRedirect) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    }

    if (record.code_challenge) {
      if (!code_verifier) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Missing code_verifier' });
      }
      const expected =
        record.code_challenge_method === 'S256'
          ? crypto
              .createHash('sha256')
              .update(code_verifier)
              .digest('base64')
              .replace(/\+/g, '-')
              .replace(/\//g, '_')
              .replace(/=+$/, '')
          : code_verifier;
      if (expected !== record.code_challenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
      }
    }

    const now = Math.floor(Date.now() / 1000);
    const accessToken = signJwt(
      {
        sub: 'pentester-demo',
        aud: client_id,
        iss: getBaseUrl(req),
        scope: record.scope,
        iat: now,
        exp: now + 3600,
      },
      config.allowAlgNone
    );

    const idToken = signJwt(
      {
        sub: 'pentester-demo',
        aud: client_id,
        iss: getBaseUrl(req),
        nonce: record.nonce || undefined,
        email: 'pentester@mock.local',
        name: 'Demo Pentester',
        iat: now,
        exp: now + 3600,
      },
      config.allowAlgNone
    );

    tokens.set(accessToken, {
      sub: 'pentester-demo',
      email: 'pentester@mock.local',
      name: 'Demo Pentester',
      scope: record.scope,
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      access_token: accessToken,
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: record.scope,
    });
  });

  router.get('/userinfo', (req, res) => {
    const auth = req.get('Authorization') || '';
    const token = auth.replace(/^Bearer\s+/i, '').trim();
    const user = tokens.get(token);
    if (!user) {
      return res.status(401).json({ error: 'invalid_token' });
    }
    return res.json(user);
  });

  return {
    router,
    getConfig: () => ({ ...config }),
    setConfig: (patch) => Object.assign(config, patch || {}),
  };
}
