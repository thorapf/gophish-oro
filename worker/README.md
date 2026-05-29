# gophish-redirector (Cloudflare Worker)

A single-file Cloudflare Worker that gates access to a GoPhish phishing
server. Filters bots and email-link sandboxes; passes real users through
to GoPhish. Authentication to GoPhish is via an HMAC-SHA256 token over
the rid, using a shared secret known to both this Worker and GoPhish.

## Deployment (no wrangler, no CLI)

1. **Cloudflare dashboard** → *Workers & Pages* → *Create application* →
   *Create Worker*. Name it whatever, e.g. `gophish-redirector`.
2. *Quick edit*. Paste the entire contents of `worker.js`. Save and deploy.
3. *Settings* → *Variables and Secrets* → add the env vars below.
4. *Settings* → *Triggers* → *Custom Domains* → add the hostname you'll
   use in campaign URLs, e.g. `redirector.example.com`. Cloudflare
   provisions the cert automatically.

## Required environment variables

| Name              | Example                                  | Purpose |
|-------------------|------------------------------------------|---------|
| `SECRET`          | 64 hex chars (32 bytes)                  | HMAC key. Must match `phish_server.redirector.secret` in GoPhish `config.json`. Generate with `openssl rand -hex 32`. |
| `PHISH_ORIGIN`    | `https://phish.example.com`              | Where the actual GoPhish phishing server lives. Origin only (no path). |

## Optional environment variables

| Name              | Example                                  | Purpose |
|-------------------|------------------------------------------|---------|
| `BOT_LANDING_URL` | `https://www.example.com/marketing`      | Where bots get 302'd. If unset, bots get a quiet `204 No Content`. |

## GoPhish-side configuration

In your GoPhish `config.json`, under `phish_server`:

```json
"redirector": {
    "secret": "<the same 64-char hex you set in the Worker SECRET env var>"
}
```

Restart GoPhish after editing `config.json`.

## How it routes

| Request to redirector            | Action |
|----------------------------------|--------|
| `GET /<path>/hi?id=<rid>`        | Worker fires a server-side GET to `<PHISH_ORIGIN>/<path>/hi?id=<rid>&token=<hmac>` (fire-and-forget). Mail client gets a `204 No Content` directly from the Worker. No reliance on image-loaders following redirects. GoPhish logs *Email Opened*. |
| `GET /<path>?id=<rid>` (layer-1 bot) | Fire-and-forget GET to `<PHISH_ORIGIN>/beep?id=<rid>&token=<hmac>` so GoPhish records a *Bot Click* event for this rid. Then 302 the bot to `BOT_LANDING_URL` (or 204). |
| `GET /<path>?id=<rid>` (layer-1 pass)| Worker serves a visually-blank HTML page with an embedded JS challenge that runs `navigator.webdriver` / plugin / WebGL / screen checks and POSTs the result to `/__verify`. |
| `POST /__verify?id=<rid>`        | JS-challenge submission. If signals look human, Worker mints `<PHISH_ORIGIN>/<path>?id=<rid>&token=<hmac>` and returns it as JSON; client-side JS does `location.replace(target)`. If signals fail, Worker fires the `/beep` event and returns 403. |
| Anything without `?id=<rid>`     | 302 to `BOT_LANDING_URL` (or 204). |

## Bot detection — two layers

### Layer 1: request-time heuristics (cheap, no JS)

Any one of these flags the request as a bot before any HTML is served:

1. **User-Agent regex** — `curl`, `wget`, `python-requests`, `HeadlessChrome`,
   `Puppeteer`, common scanner names (`Pingdom`, `Mimecast`, `ProofPoint`,
   etc.). Empty UA also flagged.
2. **ASN deny list** — datacenter ASNs (AWS, GCP, Azure, OVH, DigitalOcean,
   Hetzner, Linode, Vultr) and email-security vendor ASNs (ProofPoint,
   Mimecast, Barracuda, Symantec). Real users are almost never on these.
3. **Cloudflare's verified-bot flag** — `request.cf.botManagement.verifiedBot`
   (Googlebot, Bingbot, etc.).
4. **Sec-Fetch-Mode / Sec-Fetch-Site missing** — real browsers send these
   on every top-level navigation. Most automated tooling doesn't.
5. **Accept-Language missing** — headless tooling defaults often omit it.

Edit the `BOT_UA_RE` regex and `BLOCKED_ASNS` set inside `worker.js` to tune
for your engagement.

### Layer 2: invisible JS challenge

After layer 1 passes, the Worker serves a tiny HTML page that's visually
blank. An embedded script runs immediately and collects:

- `navigator.webdriver` (set by Selenium / Puppeteer / Playwright defaults)
- `navigator.plugins.length` and `navigator.languages.length`
- `navigator.hardwareConcurrency`
- `window.screen.width / height`
- Canvas fingerprint (last 32 chars of `toDataURL()`)
- WebGL unmasked renderer (catches "SwiftShader", "llvmpipe", "Mesa", etc.)

The signals are POSTed back to the Worker's `/__verify` endpoint. The
Worker evaluates and either returns the GoPhish target URL (with the
HMAC token) on pass, or fires the `/beep` event and returns 403. The
embedded JS does `location.replace(target)` on success; on any failure
or error, the page just stays blank.

What this catches that layer 1 doesn't:

- Headless Chrome / Puppeteer / Selenium running on residential IPs.
- Real-Chrome scanners with all the right headers but bot-shaped JS env.
- Tools that don't execute JS at all (the page stays blank, no redirect).

What it doesn't catch:

- A human analyst manually clicking the link on their workstation.
- Bot frameworks specifically tuned to evade these checks (uncommon for
  general-purpose scanners).

There's no captcha and no visible "verifying browser" message. Real
users see a blank page for ~200–500ms while JS runs and redirects.

## Landing page authoring (one rule)

Form POSTs inherit the token from the document URL only if the form's
`action` attribute is empty or absent:

```html
<!-- correct: POST goes back to the same URL, which already has &token= -->
<form method="POST">
   ...
</form>

<!-- also correct -->
<form method="POST" action="">
   ...
</form>

<!-- wrong: action="{{.URL}}" expands to the redirector hostname without
     a token, so GoPhish will reject the POST -->
<form method="POST" action="{{.URL}}">
```

If you have existing campaign Page HTML that uses `action="{{.URL}}"`, edit
it to drop the action attribute. Otherwise form submissions land at
GoPhish without a token and dead-end to `not_found_redirect_url`.

## Verifying the setup

1. Open your campaign URL in a real browser. Should land on the GoPhish
   landing page; the campaign timeline shows *Clicked Link* with your IP.
2. From a terminal:
   ```
   curl -v "https://redirector.example.com/abc?id=<your-rid>"
   ```
   Should return `204` (or 302 to `BOT_LANDING_URL`). The campaign
   timeline should show a *Bot Click* event for that rid.
3. Try direct access to GoPhish bypassing the redirector:
   ```
   curl -v "https://phish.example.com/?id=<your-rid>"
   ```
   Should return 302 to `not_found_redirect_url` (no token).

## Rotation

If you suspect the `SECRET` has leaked:
1. Generate a new value: `openssl rand -hex 32`.
2. Update the Worker env var. Save & deploy.
3. Update `phish_server.redirector.secret` in GoPhish `config.json`.
4. Restart GoPhish.

Any in-flight links signed under the old secret stop working immediately.
