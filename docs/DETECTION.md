# Detection and brand matching

The same registry and hostname checks are used for CertStream collection, URLScan hunting, and snapshot synchronization. They identify possible impersonation of reviewed Lithuanian brands; they do not prove that a site is phishing.

## Matching rules

1. Normalize the hostname and reject malformed input. Suppress every reviewed official or excluded domain and its subdomains, along with documented Microsoft Defender for Cloud Apps certificate rewrite zones.
2. Match an alias only as a complete hyphen-delimited token, or as a complete sequence of tokens within one DNS label. The same label must also contain a reviewed suspicious word, unless that matching label is itself punycode. Punycode or a threat word in a separate label is not context: `login.revolut.example` does not qualify.
3. A narrow exception covers a long alias joined directly to one suspicious prefix or suffix, such as `securerevolut` or `revolutlogin`. It also folds hyphen-delimited pieces inside that same label, allowing `rev-olut-login` while rejecting cross-label context. After folding, the remaining prefix or suffix must exactly equal one word in the suspicious-word set; arbitrary substrings such as `revolut` in `revolution` do not match. Registry entries cannot supply executable regular expressions.
4. One-edit matching uses restricted Damerau-Levenshtein distance, so insertion, deletion, substitution, or one adjacent transposition can qualify. It remains opt-in and applies only to a single-word alias listed in that brand's `fuzzyAliases`, with suspicious context in the same label or punycode evidence. Digit-bearing aliases must preserve their digits.
5. Apply the brand's `excludedTerms` before scoring. These narrowly reviewed collisions prevent mappings such as Sberbank to Swedbank or `maximo` to MAXIMA.
6. Reject ambiguous evidence. If a hostname or title matches more than one brand, or a declared brand conflicts with the current hostname match, no brand is selected.

A different top-level domain or repeated hyphens can increase a score only after valid brand evidence exists. The default minimum for CertStream collection and URLScan domain hunts is 80. Confidence is a ranking score from the public rules, not a probability.

CertStream and URLScan observations remain `suspected`. A URLScan phishing verdict can raise confidence but cannot establish current liveness or replace same-brand evidence. Only a configured HECAVEX export can publish lifecycle states such as `active`, `offline`, or `mitigated`.

## Archive revalidation

Archived observations do not keep an old match indefinitely. A CertStream hostname must produce one current brand match; synchronization uses that current match rather than trusting the archived brand label.

URLScan archives record whether brand evidence came from the domain, page title, or provider verdict. A primary-HTML hash label may also record how a related report was found, but it cannot establish the target brand by itself.

If the current hostname matcher selects a brand, it must select the row's declared brand. If it finds no brand, the row may remain only with typed title or verdict evidence. Every retained row must still resolve to a current registry brand and pass official-domain, exclusion, and collision checks. Older or untyped archive rows are rejected.

## Maintaining precision

- Record every verified first-party domain in `data/brands-lt.json`, regardless of TLD, with an authoritative source.
- Add `excludedTerms` only for demonstrated lexical collisions, and cover the full false-positive hostname with a regression test.
- Enable `fuzzyAliases` only for reviewed typo evidence with positive and negative tests.
- Do not globally allowlist shared hosting services such as `pages.dev` or `workers.dev`; attackers can obtain subdomains there.

Microsoft documents the suppressed rewrite zones in [Defender for Cloud Apps proxy troubleshooting](https://learn.microsoft.com/en-us/defender-cloud-apps/troubleshooting-proxy-url).
