# Data sources and terms

Feed operators define their own access, attribution, rate, and redistribution conditions. Review their current terms before deployment; Apache-2.0 licenses this software, not third-party data.

## CertStream and Certificate Transparency

CertStream emits Certificate Transparency log updates over a websocket. The collector reads certificate DNS names, rejects official domains, applies the public Lithuanian-brand heuristic, and archives only matching defanged domains. It does not retrieve or browse those domains.

- [CertStream documentation](https://certstream.dev/docs.html)
- [CertStream architecture](https://certstream.dev/architecture.html)
- [CaliDog CertStream client](https://github.com/CaliDog/certstream-python)

The CLI's compatibility default is `wss://certstream.calidog.io/`, matching CaliDog's client examples, but a public endpoint can accept connections without delivering current messages. Always verify nonzero message counts or configure `CERTSTREAM_URL` to a monitored endpoint. The Docker composition avoids this dependency by running the pinned open-source Rust server locally. A certificate is not proof of phishing; all CT records remain `suspected`.

The open registry is [`data/brands-lt.json`](../data/brands-lt.json). Official domains and their subdomains are allow-listed before scoring. Registry contributions should cite an official brand source and cover every known domain, regardless of TLD.

## VMRay Threat Feed

The optional adapter reads URL cards from VMRay's public page filtered to classification 39 (phishing). It is an intentionally small, best-effort HTML adapter rather than an undocumented API client.

- [VMRay public phishing feed](https://threatfeed.vmray.com/?classification=39)

It is disabled by default and requires both `VMRAY_ENABLED=true` and `VMRAY_ACCEPT_TERMS=true` after the deployer reviews the site's current terms. `VMRAY_PAGES` is bounded from 1 to 5. Page layout changes fail this source independently.

## PhishTank

PhishTank provides downloadable verified-online databases, documents hourly updates, requires a descriptive user agent, and recommends an application key for automated downloads.

- [Developer information](https://phishtank.org/developer_info.php)
- [Terms of use](https://phishtank.org/terms.php)

Set a descriptive `PHISHTANK_USER_AGENT`. `PHISHTANK_ENABLED=true` uses the officially documented rate-limited anonymous gzip download for occasional local checks; scheduled GitHub automation sets `PHISHTANK_REQUIRE_APP_KEY=true` and requires `PHISHTANK_APP_KEY`. The signed CDN redirect is followed only when its destination remains under `cdn.phishtank.com`, and decompressed output is size-limited. Confidence 95 reflects the feed's verified/online state, not HECAVEX scoring.

## OpenPhish

The OpenPhish Community Feed is disabled by default. Enable it only after reviewing its [feed options](https://openphish.com/phishing_feeds.html) and [terms](https://openphish.com/terms.html):

```text
OPENPHISH_ENABLED=true
OPENPHISH_ACCEPT_TERMS=true
```

## HECAVEX public export

`HECAVEX_FEED_URL` can point to a dedicated JSON endpoint following [the public contract](DATA-CONTRACT.md). `HECAVEX_FEED_TOKEN` is sent as a bearer token when present. Create this as a separate allow-listed view or job in the private environment. Never expose a private dashboard endpoint, database, collector API, or detector response directly.

## Screenshots

Screenshots are optional. By default, only HTTPS URLs on `urlscan.io` or its subdomains pass validation. When adding a provider, also update the `img-src` Content Security Policy in `index.html`. The dashboard loads an approved screenshot only on request, sends no referrer, and never embeds the observed phishing page.
