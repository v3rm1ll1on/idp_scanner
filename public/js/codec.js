import { $, escapeHtml, copyToClipboard } from './state.js';

export function urlEncodeComponent(text) {
  return encodeURIComponent(String(text ?? ''));
}

export function urlDecodeComponent(text, plusAsSpace = true) {
  const raw = String(text ?? '');
  const normalized = plusAsSpace ? raw.replace(/\+/g, ' ') : raw;
  return decodeURIComponent(normalized);
}

export function urlEncodeUri(text) {
  return encodeURI(String(text ?? ''));
}

export function urlDecodeUri(text) {
  return decodeURI(String(text ?? ''));
}

export function urlDoubleEncode(text) {
  return encodeURIComponent(encodeURIComponent(String(text ?? '')));
}

function splitUrlParts(input) {
  const raw = String(input ?? '').trim();
  const hashIdx = raw.indexOf('#');
  const withoutHash = hashIdx >= 0 ? raw.slice(0, hashIdx) : raw;
  const hash = hashIdx >= 0 ? raw.slice(hashIdx) : '';
  const qIdx = withoutHash.indexOf('?');

  if (qIdx >= 0) {
    return {
      prefix: withoutHash.slice(0, qIdx + 1),
      query: withoutHash.slice(qIdx + 1),
      hash,
      hasQuerySyntax: true,
    };
  }

  // Support bare query strings like "client_id=abc&redirect_uri=https%3A%2F%2F..."
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(withoutHash) && withoutHash.includes('=')) {
    return {
      prefix: '',
      query: withoutHash,
      hash,
      hasQuerySyntax: true,
    };
  }

  return {
    prefix: withoutHash,
    query: '',
    hash,
    hasQuerySyntax: false,
  };
}

export function encodeQueryValues(input) {
  const { prefix, query, hash, hasQuerySyntax } = splitUrlParts(input);
  if (!hasQuerySyntax || !query) {
    return urlEncodeComponent(input);
  }
  const encodedQuery = query
    .split('&')
    .map((pair) => {
      if (!pair) return '';
      const eqIdx = pair.indexOf('=');
      if (eqIdx < 0) return encodeURIComponent(pair);
      const key = pair.slice(0, eqIdx);
      const val = pair.slice(eqIdx + 1);
      return `${key}=${encodeURIComponent(val)}`;
    })
    .join('&');
  return `${prefix}${encodedQuery}${hash}`;
}

export function decodeQueryValues(input, plusAsSpace = true) {
  const { prefix, query, hash, hasQuerySyntax } = splitUrlParts(input);
  if (!hasQuerySyntax || !query) {
    return urlDecodeComponent(input, plusAsSpace);
  }
  const decodedQuery = query
    .split('&')
    .map((pair) => {
      if (!pair) return '';
      const eqIdx = pair.indexOf('=');
      if (eqIdx < 0) return urlDecodeComponent(pair, plusAsSpace);
      const key = urlDecodeComponent(pair.slice(0, eqIdx), plusAsSpace);
      const val = urlDecodeComponent(pair.slice(eqIdx + 1), plusAsSpace);
      return `${key}=${val}`;
    })
    .join('&');
  return `${prefix}${decodedQuery}${hash}`;
}

export function extractQueryParams(input, plusAsSpace = true) {
  const { query, hasQuerySyntax } = splitUrlParts(input);
  if (!hasQuerySyntax || !query) return [];
  return query
    .split('&')
    .filter(Boolean)
    .map((pair) => {
      const eqIdx = pair.indexOf('=');
      const rawKey = eqIdx >= 0 ? pair.slice(0, eqIdx) : pair;
      const rawVal = eqIdx >= 0 ? pair.slice(eqIdx + 1) : '';
      let key = rawKey;
      let decodedValue = rawVal;
      try {
        key = urlDecodeComponent(rawKey, plusAsSpace);
      } catch {
        // keep raw key on malformed percent encoding
      }
      try {
        decodedValue = urlDecodeComponent(rawVal, plusAsSpace);
      } catch {
        // keep raw value on malformed percent encoding
      }
      return { key, rawValue: rawVal, decodedValue };
    });
}

export function initCodecTool({ onLoadRepeater, onLoadParser } = {}) {
  const inputEl = $('codecInput');
  const outputEl = $('codecOutput');
  const statusEl = $('codecStatus');
  const plusEl = $('codecPlusAsSpace');
  const paramsEl = $('codecParamsTable');
  if (!inputEl || !outputEl) return;

  const setStatus = (msg, isError = false) => {
    if (!statusEl) return;
    statusEl.textContent = msg;
    statusEl.style.color = isError ? '#f87171' : '';
  };

  const renderParamsPreview = () => {
    if (!paramsEl) return;
    const params = extractQueryParams(inputEl.value, plusEl?.checked ?? true);
    if (params.length === 0) {
      paramsEl.innerHTML = '<div class="muted" style="padding:6px;">Paste a URL or query string (a=1&amp;b=2) to inspect decoded parameters.</div>';
      return;
    }
    const rows = params
      .map(
        (p) => `
          <tr>
            <td class="mono" style="width:140px;color:#93c5fd;">${escapeHtml(p.key)}</td>
            <td class="mono" style="word-break:break-all;">${escapeHtml(p.decodedValue)}</td>
            <td style="width:60px;text-align:right;">
              <button class="btn btn-ghost codec-copy-param" data-val="${escapeHtml(p.decodedValue)}" style="padding:2px 6px;font-size:10px;">Copy</button>
            </td>
          </tr>
        `,
      )
      .join('');
    paramsEl.innerHTML = `<table class="kv-table"><tbody>${rows}</tbody></table>`;
    paramsEl.querySelectorAll('.codec-copy-param').forEach((btn) => {
      btn.addEventListener('click', () => copyToClipboard(btn.dataset.val, 'Copied parameter value'));
    });
  };

  const runTransform = (label, fn) => {
    try {
      const result = fn(inputEl.value, plusEl?.checked ?? true);
      outputEl.value = result;
      setStatus(`${label} (${result.length} chars)`);
    } catch (err) {
      setStatus(`Error: ${err.message}`, true);
    }
  };

  $('codecEncodeCompBtn')?.addEventListener('click', () => runTransform('Encoded component', urlEncodeComponent));
  $('codecDecodeCompBtn')?.addEventListener('click', () => runTransform('Decoded component', urlDecodeComponent));
  $('codecEncodeUriBtn')?.addEventListener('click', () => runTransform('Encoded URI', urlEncodeUri));
  $('codecDecodeUriBtn')?.addEventListener('click', () => runTransform('Decoded URI', urlDecodeUri));
  $('codecDoubleEncodeBtn')?.addEventListener('click', () => runTransform('Double-encoded component', urlDoubleEncode));
  $('codecEncodeQueryBtn')?.addEventListener('click', () => runTransform('Encoded query values', encodeQueryValues));
  $('codecDecodeQueryBtn')?.addEventListener('click', () => runTransform('Decoded query values', decodeQueryValues));

  $('codecSwapBtn')?.addEventListener('click', () => {
    const prevOut = outputEl.value;
    outputEl.value = inputEl.value;
    inputEl.value = prevOut;
    renderParamsPreview();
    setStatus('Swapped Input <-> Output');
  });

  $('codecClearBtn')?.addEventListener('click', () => {
    inputEl.value = '';
    outputEl.value = '';
    renderParamsPreview();
    setStatus('Cleared');
  });

  $('codecCopyBtn')?.addEventListener('click', () => {
    const text = outputEl.value || inputEl.value;
    if (!text) return;
    copyToClipboard(text, 'Copied codec output');
    setStatus('Copied to clipboard');
  });

  $('codecToRepeaterBtn')?.addEventListener('click', () => {
    const candidate = (outputEl.value || inputEl.value).trim();
    if (!candidate) return;
    onLoadRepeater?.(candidate);
  });

  $('codecToParserBtn')?.addEventListener('click', () => {
    const candidate = (outputEl.value || inputEl.value).trim();
    if (!candidate) return;
    onLoadParser?.(candidate);
  });

  inputEl.addEventListener('input', renderParamsPreview);
  plusEl?.addEventListener('change', renderParamsPreview);
  renderParamsPreview();
}
