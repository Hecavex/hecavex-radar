from hecavex_radar.certstream import domains_from_message


def test_accepts_full_certificate_payload() -> None:
    payload = {
        "message_type": "certificate_update",
        "data": {"leaf_cert": {"all_domains": ["example.com", "*.login.example.com", 5]}},
    }
    assert domains_from_message(payload) == ["example.com", "*.login.example.com"]


def test_accepts_domains_only_payload_and_ignores_heartbeats() -> None:
    payload = {"message_type": "dns_entries", "data": ["example.lt", "*.login.example.lt"]}
    assert domains_from_message(payload) == ["example.lt", "*.login.example.lt"]
    assert domains_from_message({"message_type": "heartbeat", "data": {}}) == []
