/*
 * gophish-redirector — Cloudflare Worker
 *
 * Sits in front of the GoPhish phishing server. Filters automated visitors
 * (sandbox crawlers, email-link scanners, vulnerability bots) and only
 * redirects real browsers through to the GoPhish landing page.
 *
 * Two paths:
 *   /<anything>/hi?id=<rid>   → tracking pixel. Always 302 to GoPhish.
 *                               No bot check (mail clients are inherently
 *                               automated).
 *   /<anything>?id=<rid>      → click. Bot check runs. If pass, 302 to
 *                               GoPhish so the user hits the landing page
 *                               and GoPhish records a normal Clicked Link
 *                               event. If fail, fire-and-forget HEAD ping
 *                               to GoPhish with the configured bot UA so a
 *                               Bot Click event is recorded, then return a
 *                               benign response to the bot.
 *
 * Env vars (configure in Cloudflare dashboard → Workers → Settings → Variables):
 *   PHISH_ORIGIN      e.g. https://phish.example.com
 *   BOT_UA            must match phish_server.redirector.bot_ua in
 *                     gophish config.json
 *   BOT_LANDING_URL   where to send detected bots (optional; defaults to
 *                     a 200 No Content if unset)
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // /hi tracking pixel: redirect, no checks.
    if (/\/hi$/.test(url.pathname)) {
      return redirectToPhish(url, env);
    }

    // Anything without ?id=<rid> isn't ours — send to bot landing.
    if (!url.searchParams.get('id')) {
      return botLanding(env);
    }

    // Bot detection on the click path.
    const verdict = classify(request);
    if (verdict.bot) {
      // Fire HEAD ping to GoPhish so the admin timeline shows a Bot Click
      // for this rid. ctx.waitUntil lets us return immediately while the
      // ping flies in the background.
      const target = buildTarget(url, env);
      ctx.waitUntil(
        fetch(target, {
          method: 'HEAD',
          headers: { 'User-Agent': env.BOT_UA },
        }).catch(() => { /* best-effort */ })
      );
      return botLanding(env);
    }

    // Real user: redirect their browser to GoPhish.
    return redirectToPhish(url, env);
  },
};

// buildTarget composes the GoPhish URL preserving path and query.
function buildTarget(url, env) {
  const origin = new URL(env.PHISH_ORIGIN);
  const target = new URL(origin.toString());
  target.pathname = url.pathname;
  target.search = url.search;
  return target.toString();
}

// redirectToPhish issues a 302 to the GoPhish equivalent of this request.
// The Referrer-Policy header ensures the GoPhish hostname's referer-check
// sees redirector.example.com as the origin (not stripped).
function redirectToPhish(url, env) {
  const target = buildTarget(url, env);
  return new Response(null, {
    status: 302,
    headers: {
      'Location': target,
      'Referrer-Policy': 'origin',
      'Cache-Control': 'no-store',
    },
  });
}

// botLanding is what suspicious clients see. Either a 302 to a configurable
// URL (e.g. a marketing page) or a quiet 204.
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
// Bot classification. Each signal can independently flag a request.
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

// Substrings indicating automated tooling. Conservative — false positives
// here mean blocking a real user, so we keep the list to obvious tells.
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

// Datacenter / cloud ASNs and known security-vendor ASNs.
// AS numbers — extend as needed.
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
