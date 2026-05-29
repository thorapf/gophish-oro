# gophish-redirector (Cloudflare Worker)

A single-file Cloudflare Worker that gates access to a GoPhish phishing
server. Filters bots and email-link sandboxes; passes real users through
to GoPhish.

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
| `PHISH_ORIGIN`    | `https://phish.example.com`              | Where the actual GoPhish phishing server lives. Origin only (no path). |
| `BOT_UA`          | `Redirector-Bot`                         | User-Agent used on the HEAD ping for bot-detected visits. Must match `phish_server.redirector.bot_ua` in GoPhish `config.json`. |

## Optional environment variables

| Name              | Example                                  | Purpose |
|-------------------|------------------------------------------|---------|
| `BOT_LANDING_URL` | `https://www.example.com/marketing`      | Where bots get 302'd. If unset, bots get a quiet `204 No Content`. |

## GoPhish-side configuration

In your GoPhish `config.json`, under `phish_server`:

```json
"redirector": {
    "allowed_referer": [
        "redirector.example.com",
        "phish.example.com"
    ],
    "bot_ua": "Redirector-Bot"
}
```

- `allowed_referer` must include both the redirector hostname (where users
  arrive from) and the GoPhish hostname (where form POSTs originate).
- `bot_ua` must exactly match the Worker's `BOT_UA` env var.

## How it routes

| Request to redirector            | Action |
|----------------------------------|--------|
| `GET /<path>/hi?id=<rid>`        | 302 → `<PHISH_ORIGIN>/<path>/hi?id=<rid>`. No bot check (it's a tracking pixel; mail clients are automated). |
| `GET /<path>?id=<rid>` (bot)     | Fire-and-forget HEAD to GoPhish with `User-Agent: <BOT_UA>` so GoPhish records a *Bot Click* event. Then send the bot to `BOT_LANDING_URL` (or 204). |
| `GET /<path>?id=<rid>` (real)    | 302 → `<PHISH_ORIGIN>/<path>?id=<rid>` with `Referrer-Policy: origin` so the GoPhish referer check passes. |
| Anything without `?id=<rid>`     | Send to `BOT_LANDING_URL` (or 204). |

## Bot detection signals (no captcha, no JS challenge)

Any one of these flags the request as a bot:

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
for your engagement. Both are at the bottom of the file.

## Verifying the setup

1. Open your campaign URL in a real browser. Should land on the GoPhish
   landing page; the campaign timeline shows *Clicked Link* with your IP.
2. From a terminal:
   ```
   curl -v https://redirector.example.com/abc?id=<your-rid>
   ```
   Should return `204` (or 302 to `BOT_LANDING_URL`). The campaign
   timeline should show a *Bot Click* event.
3. Try direct access to GoPhish bypassing the redirector:
   ```
   curl -v https://phish.example.com/?id=<your-rid>
   ```
   Should return 302 to `not_found_redirect_url` (no referer). The rid is
   not burnt.

## Rotation

The `BOT_UA` value functions as a weak shared secret on the HEAD-ping
path. If you suspect leakage, rotate it: update both the Worker env var
and GoPhish `config.json`, restart GoPhish. Worker takes effect
immediately (Cloudflare propagates within seconds).
