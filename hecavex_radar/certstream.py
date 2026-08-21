from __future__ import annotations

from typing import Any


def domains_from_message(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    if value.get("message_type") == "dns_entries" and isinstance(value.get("data"), list):
        return [domain for domain in value["data"][:500] if isinstance(domain, str)]
    data = value.get("data")
    if value.get("message_type") != "certificate_update" or not isinstance(data, dict):
        return []
    leaf = data.get("leaf_cert")
    candidates: object = leaf.get("all_domains") if isinstance(leaf, dict) else None
    if not isinstance(candidates, list):
        candidates = data.get("dns_entries")
    if not isinstance(candidates, list):
        return []
    return [domain for domain in candidates[:500] if isinstance(domain, str)]
