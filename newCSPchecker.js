(async () => {
  // For each directive, we collect both a Set (for the CSP value) and an object for reasons.
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

  // For each directive, keep a reasons map: {src: [explanations]}
  const cspReasons = Object.fromEntries(Object.keys(cspDirectives).map(d => [d, {}]));
  const inlineScripts = [];
  const inlineStyles = [];
  const nonceUsage = [];
  const dataUriUsage = [];
  const evalDetected = { used: false };

  const extractOrigin = url => {
    try {
      const u = new URL(url, location.href);
      return u.origin === location.origin ? "'self'" : u.origin;
    } catch { return null; }
  };

  // SCRIPTS
  document.querySelectorAll('script').forEach(el => {
    if (el.src) {
      const src = el.src.startsWith('data:') ? 'data:' : extractOrigin(el.src);
      cspDirectives['script-src'].add(src);
      (cspReasons['script-src'][src] ||= []).push(el.outerHTML);
      if (src === 'data:') dataUriUsage.push({type: 'script', el});
    } else if (el.textContent.trim()) {
      inlineScripts.push(el.textContent.trim());
      (cspReasons['script-src']['inline'] ||= []).push(el.outerHTML.slice(0,200) + (el.outerHTML.length>200?"...":""));
      if (el.nonce) nonceUsage.push({type: 'script', value: el.nonce, el});
    }
  });

  // STYLES
  document.querySelectorAll('link[rel="stylesheet"], style').forEach(el => {
    if (el.tagName === 'LINK' && el.href) {
      const href = el.href.startsWith('data:') ? 'data:' : extractOrigin(el.href);
      cspDirectives['style-src'].add(href);
      (cspReasons['style-src'][href] ||= []).push(el.outerHTML);
      if (href === 'data:') dataUriUsage.push({type: 'style', el});
    } else if (el.textContent.trim()) {
      inlineStyles.push(el.textContent.trim());
      (cspReasons['style-src']['inline'] ||= []).push(el.outerHTML.slice(0,200) + (el.outerHTML.length>200?"...":""));
      if (/url\(['"]?data:/.test(el.textContent)) dataUriUsage.push({type:'style-inline-data', el});
      if (el.nonce) nonceUsage.push({type: 'style', value: el.nonce, el});
    }
  });

  // IMAGES
  document.querySelectorAll('img').forEach(el => {
    const src = el.src.startsWith('data:') ? 'data:' : extractOrigin(el.src);
    cspDirectives['img-src'].add(src);
    (cspReasons['img-src'][src] ||= []).push(el.outerHTML);
    if (src === 'data:') dataUriUsage.push({type:'img', el});
  });

  // FONTS
  document.querySelectorAll('link[rel="preload"][as="font"], style').forEach(el => {
    const matches = el.textContent.match(/url\(['"]?(data:|https?:\/\/[^)'"]+)/g);
    if (matches) matches.forEach(url => {
      const isData = url.includes('data:');
      const origin = isData ? 'data:' : extractOrigin(url.replace(/url\(['"]?/, ''));
      cspDirectives['font-src'].add(origin);
      (cspReasons['font-src'][origin] ||= []).push((el.tagName === 'STYLE'?el.textContent.slice(0,200):el.outerHTML)+(isData?' (data URI)':''));
      if (isData) dataUriUsage.push({type:'font-inline-data-uri', el});
    });
  });

  // FRAMES
  document.querySelectorAll('iframe').forEach(el => {
    const src = el.src.startsWith('data:') ? 'data:' : extractOrigin(el.src);
    cspDirectives['frame-src'].add(src);
    (cspReasons['frame-src'][src] ||= []).push(el.outerHTML);
    if (src === 'data:') dataUriUsage.push({type:'frame', el});
  });

  // OBJECTS/EMBEDS
  document.querySelectorAll('object,embed').forEach(el => {
    if (el.data && el.data.startsWith('data:')) {
      cspDirectives['object-src'].add('data:');
      (cspReasons['object-src']['data:'] ||= []).push(el.outerHTML);
      dataUriUsage.push({type:'object', el});
    } else if (el.data) {
      const origin = extractOrigin(el.data);
      cspDirectives['object-src'].add(origin);
      (cspReasons['object-src'][origin] ||= []).push(el.outerHTML);
    } else {
      cspDirectives['object-src'].add("'none'");
      (cspReasons['object-src']["'none'"] ||= []).push('No object/embed data specified');
    }
  });

  // XHR
  const origXHR = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m, u) {
    const o = extractOrigin(u); 
    if (o) {
      cspDirectives['connect-src'].add(o);
      (cspReasons['connect-src'][o] ||= []).push(`XHR to: ${u}`);
    }
    return origXHR.apply(this, arguments);
  };

  // Fetch
  const origFetch = window.fetch;
  window.fetch = function(u, o) {
    const org = extractOrigin(u); 
    if (org) {
      cspDirectives['connect-src'].add(org);
      (cspReasons['connect-src'][org] ||= []).push(`Fetch to: ${u}`);
    }
    return origFetch.apply(this, arguments);
  };

  // WebSockets
  const origWS = window.WebSocket;
  window.WebSocket = function(u, p) {
    const org = extractOrigin(u); 
    if (org) {
      const wsorg = org.replace(/^http/, 'ws');
      cspDirectives['connect-src'].add(wsorg);
      (cspReasons['connect-src'][wsorg] ||= []).push(`WebSocket to: ${u}`);
    }
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

  // SHA-256 hashes for inline
  async function sha256Hash(content) {
    const d = new TextEncoder().encode(content);
    const hb = await crypto.subtle.digest("SHA-256", d);
    return `'sha256-${btoa(String.fromCharCode(...new Uint8Array(hb)))}'`;
  }

  if (inlineScripts.length && !nonceUsage.find(n => n.type === 'script')) {
    for (const s of inlineScripts) {
      const hash = cryptoSupported ? await sha256Hash(s) : "'unsafe-inline'";
      cspDirectives['script-src'].add(hash);
      (cspReasons['script-src'][hash] ||= []).push('Inline script (hash shown)');
    }
  }
  if (inlineStyles.length && !nonceUsage.find(n => n.type === 'style')) {
    for (const s of inlineStyles) {
      const hash = cryptoSupported ? await sha256Hash(s) : "'unsafe-inline'";
      cspDirectives['style-src'].add(hash);
      (cspReasons['style-src'][hash] ||= []).push('Inline style (hash shown)');
    }
  }
  if (nonceUsage.length) {
    let nonces = [...new Set(nonceUsage.map(n => n.value))];
    nonces.forEach(nonce => {
      cspDirectives['script-src'].add(`'nonce-${nonce}'`);
      (cspReasons['script-src'][`'nonce-${nonce}'`] ||= []).push('Script with nonce');
      cspDirectives['style-src'].add(`'nonce-${nonce}'`);
      (cspReasons['style-src'][`'nonce-${nonce}'`] ||= []).push('Style with nonce');
    });
  }

  function cleanSet(set) {
    return [...set].filter((item, idx, arr) => arr.indexOf(item) === idx).join(' ');
  }

  // Print with explanations:
  for (const [dir, vals] of Object.entries(cspDirectives)) {
    if (vals && vals.size && (vals.size > 1 || !vals.has(undefined))) {
      console.group(`%c${dir}: %c${cleanSet(vals)};`, 'font-weight:bold;', '');
      const reasons = cspReasons[dir];
      for (const [src, els] of Object.entries(reasons)) {
        if (src === "'self'") {
          console.log(`- 'self' is required for resources loaded from the same origin.`);
        } else if (src === "'none'") {
          console.log(`- 'none' is set to block this type unless specifically needed.`);
        } else if (src === "'unsafe-inline'") {
          console.log(`- 'unsafe-inline' is present, consider replacing with hashes or nonces if possible.`);
        } else if (src.startsWith("'sha256-")) {
          console.log(`- ${src} is required for an inline resource (script/style) detected on this page.`);
        } else if (src.startsWith("'nonce-")) {
          console.log(`- ${src} is required for an inline resource using this nonce.`);
        } else if (src === "inline") {
          // Already explained above
        } else if (src === "data:") {
          console.log(`- data: is required for resources (e.g. images, styles, fonts) using data URIs.`);
        } else {
          els.forEach(e => {
            if (e.startsWith('<')) {
              console.log(`- ${src} required for this resource:\n  ${e}`);
            } else {
              console.log(`- ${src}: ${e}`);
            }
          });
        }
      }
      console.groupEnd();
    }
  }

  // Additional Reporting
  if (evalDetected.used) {
    console.warn('⚠️ eval()/Function() detected. Avoid usage, or include "unsafe-eval" in CSP at your own risk (not recommended).');
  } else {
    console.log('✅ No eval()/Function() usage detected.');
  }

  if (dataUriUsage.length) {
    console.group('📌 Data URI Usage Detected');
    dataUriUsage.forEach(({type, el}, i) => {
      console.log(`#${i+1} [${type}]`, el);
    });
    console.groupEnd();
  } else {
    console.log('✅ No Data URIs detected. Safe to remove "data:" from CSP.');
  }

  // Best practices
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

  // Report-only endpoints for CSP monitoring
  console.info("\nReport CSP violations to endpoints like:\n" +
    "  report-uri: /report-csp-violation-endpoint;\n" +
    '  report-to: {"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"/report-csp-violation-endpoint"}]};\n');
})();
