# Matcher regression corpus

`lithuanian-brands-v1.json` is a versioned, reviewable safety contract for the public domain matcher. It contains only reserved-domain synthetic examples and reviewed official domains. Active victim URLs do not belong here.

The corpus records expected brand, score band, public reason codes, or an explicit rejection reason. Unicode processing is pinned to UTS #46 nontransitional STD3 handling through `idna` and confusable/script evidence derived from the pinned UTS #39 data in `confusable-homoglyphs`.

Confusable skeletons are internal comparison material. They are never published, and Unicode evidence alone is never a phishing verdict.

`restricted-identifier` is Radar's conservative evidence reason for an alias-confusable identifier outside its expected Latin-only profile. It is derived from pinned UTS #39 script and confusable data; it is not an implementation of Unicode's formal restriction-level algorithm and must not be described as one.
