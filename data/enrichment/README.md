# Bounded domain context

`domain-context.json` is the credential-free state produced for candidates
already present in the public Radar snapshot. The collector performs only
DNS-over-HTTPS queries and RDAP registration lookups. It never visits candidate
web pages, submits forms, executes JavaScript, or stores registrant contacts.

The state retains defanged DNS answers, the lowest observed TTL, selected
registration lifecycle timestamps, registrar name, status codes, collection
time, and a rotating cursor. Missing context means unknown, not benign.
