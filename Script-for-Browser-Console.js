(async () => {
  const cryptoSupported = window.crypto && crypto.subtle && crypto.subtle.digest;
  const cspDirectives = {
    'default-src': new Set(["'self'"]),
    'script-src': new Set(["'self'"]),
    'style-src': new Set(["'self'"]),
    'img-src': new Set(["'self'"]),
    'font-src': new Set(["'self'"]),
    'frame-src': new Set(["'self'"]),
    'connect-src': new Set(["'self'"]),
    'object-src': new Set(["'none'"]),
    'frame-ancestors': new Set(["'self'"]),
    'base-uri': new Set(["'self'"]),
    'form-action': new Set(["'self'"])
  };
  const inlineScripts = [];
  const inlineStyles = [];
  const evalDetected = { used: false };
  const dataUriUsage = [];
  const nonceUsage = [];

  const extractOrigin = url => {
    try {
      const u = new URL(url, location.href);
      return u.origin === location.origin ? "'self'" : u.origin;
    } catch { return null; }
  };

  const logDataUri = (type, el) => dataUriUsage.push({type, el});

  // --- Collect resource usages
  // Scripts
  document.querySelectorAll('script').forEach(el => {
    if (el.src) {
      const src = el.src.startsWith('data:') ? (logDataUri('script', el), 'data:') : extractOrigin(el.src);
      if (src) cspDirectives['script-src'].add(src);
    } else if (el.textContent.trim()) {
      inlineScripts.push(el.textContent.trim());
      if (el.nonce) nonceUsage.push({type: 'script', value: el.nonce, el});
    }
  });

  // Stylesheets
  document.querySelectorAll('link[rel="stylesheet"], style').forEach(el => {
    if (el.tagName === 'LINK' && el.href) {
      const href = el.href.startsWith('data:') ? (logDataUri('style', el), 'data:') : extractOrigin(el.href);
      if (href) cspDirectives['style-src'].add(href);
    } else if (el.textContent.trim()) {
      inlineStyles.push(el.textContent.trim());
      if (/url\(['"]?data:/.test(el.textContent)) logDataUri('style-inline-data', el);
      if (el.nonce) nonceUsage.push({type: 'style', value: el.nonce, el});
    }
  });

  // Images
  document.querySelectorAll('img').forEach(el => {
    const src = el.src.startsWith('data:') ? (logDataUri('img', el), 'data:') : extractOrigin(el.src);
    if (src) cspDirectives['img-src'].add(src);
  });

  // Fonts
  document.querySelectorAll('link[rel="preload"][as="font"], style').forEach(el => {
    const matches = el.textContent.match(/url\(['"]?(data:|https?:\/\/[^)'"]+)/g);
    if (matches) matches.forEach(url => {
      url.includes('data:') && logDataUri('font-inline-data-uri', el);
      const origin = url.includes('data:') ? 'data:' : extractOrigin(url.replace(/url\(['"]?/, ''));
      if (origin) cspDirectives['font-src'].add(origin);
    });
  });

  // Frames
  document.querySelectorAll('iframe').forEach(el => {
    const src = el.src.startsWith('data:') ? (logDataUri('frame', el), 'data:') : extractOrigin(el.src);
    if (src) cspDirectives['frame-src'].add(src);
  });

  // Object/Embed (should be rare, audit if found)
  document.querySelectorAll('object,embed').forEach(el => {
    if (el.data && el.data.startsWith('data:')) logDataUri('object', el);
    else if (el.data) cspDirectives['object-src'].add(extractOrigin(el.data));
    else cspDirectives['object-src'].add("'none'");
  });

  // Intercept XHR
  const origXHR = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m, u) {
    const o = extractOrigin(u); o && cspDirectives['connect-src'].add(o);
    return origXHR.apply(this, arguments);
  };

  // Intercept fetch
  const origFetch = window.fetch;
  window.fetch = function(u, o) {
    const org = extractOrigin(u); org && cspDirectives['connect-src'].add(org);
    return origFetch.apply(this, arguments);
  };

  // Intercept WebSockets
  const origWS = window.WebSocket;
  window.WebSocket = function(u, p) {
    const org = extractOrigin(u); org && cspDirectives['connect-src'].add(org.replace(/^http/, 'ws'));
    return new origWS(u, p);
  };

  // Detect eval
  window.eval = new Proxy(window.eval, {
    apply(target, thisArg, args) {
      evalDetected.used = true;
      return Reflect.apply(target, thisArg, args);
    }
  });
  window.Function = new Proxy(window.Function, {
    construct(target, args) {
      evalDetected.used = true;
      return Reflect.construct(target, args);
    }
  });

  // Wait for dynamic content
  await new Promise(r => setTimeout(r, 6000));

  // Hashing for inline
  async function sha256Hash(content) {
    const d = new TextEncoder().encode(content);
    const hb = await crypto.subtle.digest("SHA-256", d);
    return `'sha256-${btoa(String.fromCharCode(...new Uint8Array(hb)))}'`;
  }

  // Add hashes or note nonce
  if (inlineScripts.length && !nonceUsage.find(n => n.type === 'script')) {
    for (const s of inlineScripts) {
      cspDirectives['script-src'].add(cryptoSupported ? await sha256Hash(s) : "'unsafe-inline'");
    }
  }
  if (inlineStyles.length && !nonceUsage.find(n => n.type === 'style')) {
    for (const s of inlineStyles) {
      cspDirectives['style-src'].add(cryptoSupported ? await sha256Hash(s) : "'unsafe-inline'");
    }
  }
  if (nonceUsage.length) {
    // Recommend using nonce if present
    let nonces = [...new Set(nonceUsage.map(n => n.value))];
    nonces.forEach(nonce => {
      cspDirectives['script-src'].add(`'nonce-${nonce}'`);
      cspDirectives['style-src'].add(`'nonce-${nonce}'`);
    });
  }

  // Output
  function cleanSet(set) {
    // Remove default 'self' if other origins are present
    const arr = Array.isArray(set) ? set : [...set];
    return arr.filter((item, idx) => arr.indexOf(item) === idx).join(' ');
  }

  // ---- Final CSP Output
  console.group('🔒 Final CSP Recommendation');
  Object.entries(cspDirectives).forEach(([dir, vals]) => {
    if (vals && vals.size && (vals.size > 1 || !vals.has(undefined)))
      console.log(`%c${dir}: %c${cleanSet(vals)};`, 'font-weight:bold;', '');
  });
  // Report-only endpoints for CSP monitoring
  console.log("%creport-uri: %c/report-csp-violation-endpoint;", 'font-weight:bold;', 'color:#007ACC;');
  console.log("%creport-to: %c{\"group\":\"csp-endpoint\",\"max_age\":10886400,\"endpoints\":[{\"url\":\"/report-csp-violation-endpoint\"}]};", 'font-weight:bold;', 'color:#007ACC;');
  console.groupEnd();

  // Inline and nonce suggestions
  if (inlineScripts.length && !nonceUsage.find(n => n.type === 'script')) {
    console.group('📜 Inline Scripts Detected (Hashes below)');
    for (const s of inlineScripts) {
      const hash = cryptoSupported ? await sha256Hash(s) : "'unsafe-inline'";
      console.log(hash, s.slice(0, 120), '...');
    }
    console.groupEnd();
  }
  if (inlineStyles.length && !nonceUsage.find(n => n.type === 'style')) {
    console.group('🎨 Inline Styles Detected (Hashes below)');
    for (const s of inlineStyles) {
      const hash = cryptoSupported ? await sha256Hash(s) : "'unsafe-inline'";
      console.log(hash, s.slice(0, 120), '...');
    }
    console.groupEnd();
  }
  if (nonceUsage.length) {
    console.group('🔑 Nonce Attributes Detected');
    nonceUsage.forEach(({type, value, el}) =>
      console.log(`[${type}] nonce="${value}"`, el));
    console.groupEnd();
    console.info('➡️ CSP nonce detected. Consider adopting a nonce-based CSP for inline scripts/styles.');
  }

  if (evalDetected.used) {
    console.warn('⚠️ eval()/Function() detected. Avoid usage, or include "unsafe-eval" in CSP at your own risk (not recommended).');
  } else {
    console.log('✅ No eval()/Function() usage detected.');
  }

  if (dataUriUsage.length) {
    console.group('📌 Data URI Usage Detected (reason for data: in CSP)');
    dataUriUsage.forEach(({type, el}, i) =>
      console.log(`#${i+1} [${type}]`, el));
    console.groupEnd();
  } else {
    console.log('✅ No Data URIs detected. Safe to remove "data:" from CSP.');
  }

  // Best practices summary
  console.info('\n🔑 Best Practices:\n' +
    '- Use "object-src \'none\'" unless you absolutely need to embed objects.\n' +
    '- Use "frame-ancestors" to limit which sites can embed yours.\n' +
    '- Use "base-uri \'self\'" to prevent <base> tag attacks.\n' +
    '- Use "form-action \'self\'" to restrict where forms can post.\n' +
    '- Use "report-uri" or "report-to" to monitor violations.\n' +
    '- Prefer hashes or nonces over "unsafe-inline".\n' +
    '- Remove "data:" from directives unless explicitly needed (see above).\n' +
    '- Minimize allowed domains for each directive.\n' +
    '- Regularly re-run CSP audits after code or dependency changes.'
  );
})();
