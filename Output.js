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

  const cspReasons = Object.fromEntries(Object.keys(cspDirectives).map(d => [d, {}]));
  const inlineScripts = [];
  const inlineStyles = [];
  const nonceUsage = [];
  const dataUriUsage = [];
  const evalDetected = { used: false };
  let htmlOutput = "";

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

  // --- HTML output
  htmlOutput += `<html><head><meta charset="utf-8"><title>CSP Analyzer Report</title>
    <style>body{font-family:sans-serif;max-width:900px;margin:1em auto;}
    h1,h2{color:#22456B} code{background:#eee;padding:2px 4px;border-radius:2px;}
    .block{background:#f7fafd;padding:8px;border-radius:6px;margin-bottom:8px;word-break:break-word}
    .explain{color:#333;padding:6px 10px;background:#fbfcff;border-left:4px solid #d6eaff;margin:4px 0 8px 0;}
    details summary{font-weight:bold;}
    </style></head><body>`;
  htmlOutput += `<h1>CSP Analyzer Report</h1>`;
  htmlOutput += `<p>Page: <code>${location.href}</code></p>`;

  // CSP Summary
  htmlOutput += `<h2>Recommended CSP Directives</h2><div class="block"><pre style="font-size:1em;">`;
  Object.entries(cspDirectives).forEach(([dir, vals]) => {
    if (vals && vals.size && (vals.size > 1 || !vals.has(undefined)))
      htmlOutput += `${dir}: ${cleanSet(vals)};\n`;
  });
  htmlOutput += `report-uri: /report-csp-violation-endpoint;\n`;
  htmlOutput += `report-to: {"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"/report-csp-violation-endpoint"}]};\n`;
  htmlOutput += `</pre></div>`;

  // Details for each directive
  htmlOutput += `<h2>Directive Explanations and Triggering Elements</h2>`;
  for (const [dir, vals] of Object.entries(cspDirectives)) {
    if (vals && vals.size && (vals.size > 1 || !vals.has(undefined))) {
      htmlOutput += `<details open><summary><code>${dir}: ${cleanSet(vals)}</code></summary>`;
      const reasons = cspReasons[dir];
      for (const [src, els] of Object.entries(reasons)) {
        htmlOutput += `<div class="explain"><b>${src}</b><ul>`;
        if (src === "'self'") {
          htmlOutput += `<li>'self' is required for resources loaded from the same origin.</li>`;
        } else if (src === "'none'") {
          htmlOutput += `<li>'none' blocks this resource unless specifically needed.</li>`;
        } else if (src === "'unsafe-inline'") {
          htmlOutput += `<li>'unsafe-inline' is present, consider replacing with hashes or nonces if possible.</li>`;
        } else if (src.startsWith("'sha256-")) {
          htmlOutput += `<li>${src} is required for an inline resource (script/style) detected on this page.</li>`;
        } else if (src.startsWith("'nonce-")) {
          htmlOutput += `<li>${src} is required for an inline resource using this nonce.</li>`;
        } else if (src === "inline") {
          // Already explained above
        } else if (src === "data:") {
          htmlOutput += `<li>data: is required for resources (e.g. images, styles, fonts) using data URIs.</li>`;
        }
        els.forEach(e => {
          if (e.startsWith('<')) {
            htmlOutput += `<li><details><summary>Triggering element:</summary><pre style="white-space:pre-wrap;font-size:.98em">${e.replace(/</g,"&lt;")}</pre></details></li>`;
          } else {
            htmlOutput += `<li>${e}</li>`;
          }
        });
        htmlOutput += `</ul></div>`;
      }
      htmlOutput += `</details>`;
    }
  }

  // Additional Reporting
  htmlOutput += `<h2>Special Cases & Security Notes</h2><div class="block">`;
  if (evalDetected.used) {
    htmlOutput += `<b>⚠️ <code>eval()</code> or <code>Function()</code> detected.</b> Avoid usage, or include <code>unsafe-eval</code> in CSP at your own risk (not recommended).<br>`;
  } else {
    htmlOutput += `✅ No <code>eval()</code> or <code>Function()</code> usage detected.<br>`;
  }
  if (dataUriUsage.length) {
    htmlOutput += `<br><b>📌 Data URI Usage Detected:</b><ul>`;
    dataUriUsage.forEach(({type, el}, i) => {
      htmlOutput += `<li>[${type}] <details><summary>Show element</summary><pre style="white-space:pre-wrap">${el.outerHTML.replace(/</g,"&lt;")}</pre></details></li>`;
    });
    htmlOutput += `</ul>`;
  } else {
    htmlOutput += `✅ No Data URIs detected. Safe to remove <code>data:</code> from CSP.<br>`;
  }
  htmlOutput += `</div>`;

  // Nonce explanations
  if (nonceUsage.length) {
    htmlOutput += `<h2>Nonce Attributes Detected</h2><div class="block"><ul>`;
    nonceUsage.forEach(({type, value, el}) =>
      htmlOutput += `<li>[${type}] nonce="${value}" <details><summary>Show element</summary><pre style="white-space:pre-wrap">${el.outerHTML.replace(/</g,"&lt;")}</pre></details></li>`);
    htmlOutput += `</ul><p>➡️ CSP nonce detected. Consider adopting a nonce-based CSP for inline scripts/styles.</p></div>`;
  }

  // Best practices
  htmlOutput += `<h2>Best Practices</h2><div class="block"><ul>
    <li>Use <code>object-src 'none'</code> unless you absolutely need to embed objects.</li>
    <li>Use <code>frame-ancestors</code> to limit which sites can embed yours.</li>
    <li>Use <code>base-uri 'self'</code> to prevent <code>&lt;base&gt;</code> tag attacks.</li>
    <li>Use <code>form-action 'self'</code> to restrict where forms can post.</li>
    <li>Use <code>report-uri</code> or <code>report-to</code> to monitor violations.</li>
    <li>Prefer hashes or nonces over <code>unsafe-inline</code>.</li>
    <li>Remove <code>data:</code> from directives unless explicitly needed (see above).</li>
    <li>Minimize allowed domains for each directive.</li>
    <li>Regularly re-run CSP audits after code or dependency changes.</li>
  </ul></div>`;

  htmlOutput += `<h2>Reporting Endpoints</h2>
  <div class="block">
  <code>report-uri: /report-csp-violation-endpoint;</code><br>
  <code>report-to: {"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"/report-csp-violation-endpoint"}]};</code>
  </div>`;

  htmlOutput += `<footer style="margin-top:2em;font-size:90%;color:#888;">Generated by CSP Analyzer<br>${new Date().toLocaleString()}</footer></body></html>`;

  // --- Download file ---
  const blob = new Blob([htmlOutput], {type: 'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'csp-analyzer-report.html';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  // --- Also log minimal summary to console
  console.log('CSP Analyzer HTML report downloaded as csp-analyzer-report.html');
})();
