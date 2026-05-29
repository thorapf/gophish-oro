/*
 * gophish-redirector — Cloudflare Worker
 *
 * Sits in front of the GoPhish phishing server. Filters automated visitors
 * (sandbox crawlers, email-link scanners, vulnerability bots) and only
 * redirects real browsers through to the GoPhish landing page.
 *
 * Authentication to GoPhish is via an HMAC-SHA256 token computed over the
 * rid (?id=<uuid>) using a shared secret. The token is appended to every
 * URL the Worker sends to GoPhish (either via 302 Location or via
 * server-side fetch). GoPhish rejects any request whose ?token= doesn't
 * recompute to the expected HMAC. The rid one-shot burn provides replay
 * protection on top.
 *
 * Endpoints:
 *   /<anything>/hi?id=<rid>   → tracking pixel. Worker computes token and
 *                               302s to <PHISH_ORIGIN>/<anything>/hi
 *                               with ?id=&token=. No bot check (mail
 *                               clients are inherently automated).
 *   /<anything>?id=<rid>      → click. Bot check runs.
 *                               If bot: server-side fetch
 *                               <PHISH_ORIGIN>/beep?id=&token=
 *                               so a Bot Click event is recorded in
 *                               GoPhish. Worker returns benign response.
 *                               If real: 302 to <PHISH_ORIGIN>/<path>
 *                               with ?id=&token= so the user's browser
 *                               navigates to GoPhish's landing page.
 *
 * Env vars (configure in Cloudflare dashboard → Workers → Settings → Variables):
 *   SECRET            64-char hex string. Must match
 *                     phish_server.redirector.secret in GoPhish config.json.
 *   PHISH_ORIGIN      e.g. https://phish.example.com
 *   BOT_LANDING_URL   where detected bots get 302'd (optional;
 *                     unset → 204 No Content).
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const rid = url.searchParams.get('id');
    if (!rid) return botLanding(env);

    // Normalize PHISH_ORIGIN — strip any trailing slash so concatenation
    // with url.pathname (which starts with /) doesn't produce a double
    // slash in the redirect Location.
    const origin = (env.PHISH_ORIGIN || '').replace(/\/+$/, '');

    // Derive HMAC-SHA256(secret, rid) → hex.
    const key = await crypto.subtle.importKey(
      'raw',
      hexToBytes(env.SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(rid));
    const token = toHex(new Uint8Array(sigBuf));

    // /hi tracking pixel — Worker fires a server-side GET to GoPhish so
    // the open event is logged, then returns 204 to the mail client.
    // Avoids relying on image-loaders / mail-client proxies following 302
    // redirects (some don't).
    if (/\/hi$/.test(url.pathname)) {
      const target = `${origin}${url.pathname}?id=${encodeURIComponent(rid)}&token=${token}`;
      ctx.waitUntil(
        fetch(target, { method: 'GET' }).catch(() => { /* best-effort */ })
      );
      return new Response(null, {
        status: 204,
        headers: { 'Cache-Control': 'no-store' },
      });
    }

    // Click path — run bot detection.
    const verdict = classify(request);
    if (verdict.bot) {
      // Server-side GET to GoPhish's /beep endpoint so the timeline shows
      // a Bot Click event for this rid. Fire-and-forget; the response
      // body is irrelevant.
      const beepTarget = `${origin}/beep?id=${encodeURIComponent(rid)}&token=${token}`;
      ctx.waitUntil(
        fetch(beepTarget, { method: 'GET' }).catch(() => { /* best-effort */ })
      );
      return botLanding(env);
    }

    // Real user — redirect to GoPhish landing page.
    const target = `${origin}${url.pathname}?id=${encodeURIComponent(rid)}&token=${token}`;
    return new Response(null, {
      status: 302,
      headers: { 'Location': target, 'Cache-Control': 'no-store' },
    });
  },
};

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

function botLanding(env) {
  if (env.BOT_LANDING_URL) {
    return new Response(null, {
      status: 302,
      headers: { 'Location': env.BOT_LANDING_URL, 'Cache-Control': 'no-store' },
    });
  }
  return new Response(null, { status: 204 });
}

// ─────────────────────────────────────────────────────────────────────
// Bot classification. Any one signal can flag a request.
// ─────────────────────────────────────────────────────────────────────

function classify(request) {
  const cf = request.cf || {};
  const ua = request.headers.get('user-agent') || '';
  const reasons = [];

  // 1. Known bot/scanner User-Agents.
  if (BOT_UA_RE.test(ua) || !ua) {
    reasons.push('ua');
  }

  // 2. Datacenter / scanner ASNs. Real users on home/mobile networks are
  // virtually never on these. Customize for your engagement.
  if (BLOCKED_ASNS.has(cf.asn)) {
    reasons.push('asn');
  }

  // 3. Cloudflare's own verified-bot flag (Googlebot, Bingbot, etc.).
  if (cf.botManagement && cf.botManagement.verifiedBot) {
    reasons.push('verifiedBot');
  }

  // 4. Missing Sec-Fetch-* headers on a navigation. Real browsers send
  //    these on top-level navigations; most automated tools don't.
  const secFetchMode = request.headers.get('sec-fetch-mode');
  const secFetchSite = request.headers.get('sec-fetch-site');
  if (!secFetchMode || !secFetchSite) {
    reasons.push('sec-fetch');
  }

  // 5. Missing Accept-Language. Headless tooling defaults often omit it.
  if (!request.headers.get('accept-language')) {
    reasons.push('accept-language');
  }

  return { bot: reasons.length > 0, reasons };
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
  // Major cloud providers
  15169,  // Google
  8075,   // Microsoft
  16509,  // AWS
  14618,  // AWS
  13335,  // Cloudflare
  16276,  // OVH
  14061,  // DigitalOcean
  20473,  // Vultr / Choopa
  24940,  // Hetzner
  63949,  // Linode
  396982, // Google Cloud
  // Email-security vendors
  26211,  // ProofPoint
  22843,  // Mimecast
  14637,  // Barracuda
  21948,  // Symantec
  8987,   // Amazon (used by many security products)
]);
