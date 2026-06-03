# gophish-redirector (Cloudflare Worker)

A single-file Cloudflare Worker that gates access to a GoPhish phishing
server. Filters bots and email-link sandboxes; passes real users through
to GoPhish. Authentication to GoPhish is via an **IP-bound signed URL**:
after the bot checks pass, the Worker appends `&sig=<hmac>` where
`sig = HMAC-SHA256(secret, id + "." + CF-Connecting-IP)`, using a shared
secret known to both this Worker and GoPhish. Because both sit behind
Cloudflare, GoPhish sees the same client IP in the `CF-Connecting-IP`
header and recomputes an identical signature. There is **no expiry**: a
visitor reloading from the same IP is served indefinitely, while the same
URL replayed from any other network — a Safe Browsing verification crawl,
a mail scanner, an analyst on a different box — computes a different IP,
fails the signature, and is dead-ended to `<PHISH_ORIGIN>/404`.

The server-side-fetched `/hi` and `/beep` endpoints are signed against the
id alone (`sig = HMAC-SHA256(secret, id)`), because the Worker — not the
target's browser — issues those requests, so the IP GoPhish sees on them is
the Worker's, not the visitor's.

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
| `GET /<path>/hi?id=<rid>`        | Worker fires a server-side GET to `<PHISH_ORIGIN>/<path>/hi?id=<rid>&sig=<hmac>` (fire-and-forget; `sig` over the id alone). Mail client gets a `204 No Content` directly from the Worker. No reliance on image-loaders following redirects. GoPhish logs *Email Opened*. |
| `GET /<path>?id=<rid>`           | Worker serves the **press-and-hold page** — a visible button the visitor must hold for ~1.2s. No User-Agent, ASN, or fingerprint check. |
| `POST /__verify?id=<rid>`        | Sent by the page once the hold completes. Worker mints `<PHISH_ORIGIN>/<path>?id=<rid>&sig=<hmac>` where `sig = HMAC(secret, id + "." + CF-Connecting-IP)` and returns it as JSON; the page does `location.replace(target)`. |
| Anything without `?id=<rid>`     | 302 to `<PHISH_ORIGIN>/404`. |

`<PHISH_ORIGIN>/404` has no dedicated route on GoPhish: the catch-all sees
no valid signature and forwards to GoPhish's `not_found_redirect_url`. So
every dead-end — no id or bad path — funnels through GoPhish to a single
benign destination.

There is no expiry and no per-rid burn. The signed landing URL stays valid
for as long as the visitor keeps the same `CF-Connecting-IP`, so reloads and
slow form submissions just work without any round trip back through the
Worker. If the visitor's egress IP changes (e.g. a mobile network handoff),
the old signed URL stops validating and dead-ends to `<PHISH_ORIGIN>/404`;
re-clicking the original campaign link routes back through the Worker, which
re-runs the bot checks and mints a fresh IP-bound URL.

> **Note on IPv6:** the signature binds to the exact `CF-Connecting-IP`
> string. IPv6 privacy-extension addresses can rotate within a prefix
> mid-session; if you see legitimate IPv6 targets dead-ending on reload,
> normalize the IP to its `/64` prefix identically in both `worker.js`
> (`signedParamsIP`) and gophish (`clientIP`) before hashing.

## Bot defense — press and hold

The click page (`GET /<path>?id=<rid>`) is a single visible card with a
**Press & Hold** button. The visitor must hold it for `HOLD_MS` (default
1200ms, a constant in `worker.js`); a progress bar fills as they hold.
Releasing early resets it. Only when the bar fills does the page POST to
`/__verify` and `location.replace` to the IP-bound landing URL the Worker
returns.

There is no User-Agent regex, no ASN deny list, and no environment
fingerprinting. The gate is simply: *execute JS and perform a sustained
held-pointer gesture.*

What this stops:

- Non-JS link scanners and mailbox prefetchers — they fetch the page, never
  run the script, never POST, and so never reach GoPhish.
- Plain crawlers that follow links but don't simulate a held-pointer gesture.

What it does **not** stop (accepted trade-off for simplicity):

- A headless browser specifically scripted to dispatch the press-and-hold.
- A client that POSTs to `/__verify` directly — the gesture is enforced
  client-side only; the server trusts the POST. (Replay of the *resulting*
  landing URL from another network is still blocked by the IP-bound
  signature.)
- A human analyst who manually holds the button.

To change the hold time, edit `HOLD_MS`. To restyle the card, edit
`pressHoldHTML` in `worker.js`.

> The `/beep` *Bot Click* signal is no longer fired by the Worker (nothing
> classifies bots now). GoPhish's `/beep` route still exists but is unused;
> leave it or remove it as you like.

## Landing page authoring (one rule)

Form POSTs inherit the token from the document URL only if the form's
`action` attribute is empty or absent:

```html
<!-- correct: POST goes back to the same URL, which already has &sig= and is
     from the same browser/IP, so the IP-bound signature validates -->
<form method="POST">
   ...
</form>

<!-- also correct -->
<form method="POST" action="">
   ...
</form>

<!-- wrong: action="{{.URL}}" expands to the redirector hostname without
     a signature, so GoPhish will reject the POST -->
<form method="POST" action="{{.URL}}">
```

If you have existing campaign Page HTML that uses `action="{{.URL}}"`, edit
it to drop the action attribute. Otherwise form submissions land at
GoPhish without a signature and dead-end to `not_found_redirect_url`.

## Verifying the setup

1. Open your campaign URL in a real browser. You should see the press-and-hold
   card; hold the button for ~1.2s and you land on the GoPhish landing page,
   with the campaign timeline showing *Clicked Link* and your IP.
2. From a terminal:
   ```
   curl -s "https://redirector.example.com/abc?id=<your-rid>"
   ```
   With no UA/ASN blocking, this now returns the **press-and-hold HTML**
   (`200`). `curl` doesn't run JS or perform the gesture, so it never POSTs
   to `/__verify` and never reaches a landing page — which is the point.
3. Try direct access to GoPhish bypassing the redirector:
   ```
   curl -v "https://phish.example.com/?id=<your-rid>"
   ```
   Should return 302 to `not_found_redirect_url` (no valid signature).

## Rotation

If you suspect the `SECRET` has leaked:
1. Generate a new value: `openssl rand -hex 32`.
2. Update the Worker env var. Save & deploy.
3. Update `phish_server.redirector.secret` in GoPhish `config.json`.
4. Restart GoPhish.

Any in-flight links signed under the old secret stop working immediately.
