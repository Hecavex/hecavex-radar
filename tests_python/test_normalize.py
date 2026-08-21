from hecavex_radar.models import RawSignal
from hecavex_radar.normalize import merge_signals, prepare_signal

NOW = "2026-08-21T10:00:00.000Z"


def test_normalizes_metadata_without_private_scoring() -> None:
    signal = prepare_signal(
        RawSignal(
            url="https://login.example.test/path?recipient=person@example.com",
            source="HECAVEX",
            first_seen="2026-08-21T08:00:00Z",
            last_seen="2026-08-21T09:00:00Z",
            status="potential",
            brand="Example Bank",
            host="AS64500 · 192.0.2.10",
            confidence=77.6,
        ),
        NOW,
    )
    assert signal is not None
    assert signal["url"] == "hxxps://login[.]example[.]test/path"
    assert signal["domain"] == "login[.]example[.]test"
    assert signal["status"] == "suspected"
    assert signal["brand"] == "Example Bank"
    assert signal["host"] == "AS64500 · 192[.]0[.]2[.]10"
    assert signal["confidence"] == 78


def test_merges_duplicate_paths_and_retains_strongest_context() -> None:
    first = prepare_signal(
        RawSignal(
            url="https://login.example.test/path?one=1",
            source="URLScan",
            first_seen="2026-08-21T07:00:00Z",
            last_seen="2026-08-21T08:00:00Z",
            status="online",
            confidence=95,
        ),
        NOW,
    )
    second = prepare_signal(
        RawSignal(
            url="https://login.example.test/path?two=2",
            source="HECAVEX",
            first_seen="2026-08-21T06:00:00Z",
            last_seen="2026-08-21T09:00:00Z",
            status="suspected",
            brand="Example Bank",
            confidence=80,
        ),
        NOW,
    )
    assert first is not None and second is not None
    merged = merge_signals([first, second], 10)
    assert len(merged) == 1
    assert merged[0]["firstSeen"] == "2026-08-21T06:00:00.000Z"
    assert merged[0]["lastSeen"] == "2026-08-21T09:00:00.000Z"
    assert merged[0]["sources"] == ["HECAVEX", "URLScan"]
    assert merged[0]["status"] == "suspected"
    assert merged[0]["brand"] == "Example Bank"
    assert merged[0]["confidence"] == 95


def test_merge_uses_the_newest_status_and_non_null_host_metadata() -> None:
    older = prepare_signal(
        RawSignal(
            url="https://secure.example.test",
            source="URLScan",
            last_seen="2026-08-21T08:00:00Z",
            status="active",
            host="old.example.net",
        ),
        NOW,
    )
    newer = prepare_signal(
        RawSignal(
            url="https://secure.example.test",
            source="HECAVEX",
            last_seen="2026-08-21T09:00:00Z",
            status="offline",
            host="new.example.net",
        ),
        NOW,
    )
    assert older is not None and newer is not None

    merged = merge_signals([newer, older], 10)

    assert merged[0]["status"] == "offline"
    assert merged[0]["host"] == "new[.]example[.]net"


def test_merge_drops_a_host_with_conflicting_brand_evidence() -> None:
    first = prepare_signal(
        RawSignal(url="https://secure.example.test", source="URLScan", brand="Swedbank"),
        NOW,
    )
    second = prepare_signal(
        RawSignal(url="https://secure.example.test", source="HECAVEX", brand="Revolut"),
        NOW,
    )
    assert first is not None and second is not None

    assert merge_signals([first, second], 10) == []


def test_clamps_untrusted_future_observation_times() -> None:
    signal = prepare_signal(
        RawSignal(
            url="https://secure.example.test",
            source="HECAVEX",
            first_seen="9999-01-01T00:00:00Z",
            last_seen="9999-01-01T00:00:00Z",
        ),
        NOW,
    )
    assert signal is not None
    assert signal["firstSeen"] == NOW
    assert signal["lastSeen"] == NOW


def test_caps_sorted_output() -> None:
    old = prepare_signal(RawSignal(url="old.example.test", source="A", last_seen="2026-08-20"), NOW)
    new = prepare_signal(RawSignal(url="new.example.test", source="B", last_seen="2026-08-21"), NOW)
    assert old is not None and new is not None
    assert merge_signals([old, new], 1)[0]["domain"] == "new[.]example[.]test"


def test_defangs_ipv6_host_metadata() -> None:
    signal = prepare_signal(
        RawSignal(url="ipv6.example.test", source="HECAVEX", host="AS64500 · 2001:db8::4"),
        NOW,
    )
    assert signal is not None
    assert signal["host"] == "AS64500 · 2001[:]db8[:][:]4"


def test_defangs_domain_names_in_host_metadata() -> None:
    signal = prepare_signal(
        RawSignal(url="host.example.test", source="HECAVEX", host="Edge at node.provider.example"),
        NOW,
    )
    assert signal is not None
    assert signal["host"] == "Edge at node[.]provider[.]example"


def test_keeps_only_safe_urlscan_evidence() -> None:
    digest = "a" * 64
    signal = prepare_signal(
        RawSignal(
            url="secure-swedbank.example",
            source="URLScan",
            screenshot_url="https://urlscan.io/screenshots/example.png",
            reference_url="https://urlscan.io/result/11111111-1111-1111-1111-111111111111/",
            hashes=[digest, digest, "not-a-hash"],
        ),
        NOW,
    )
    assert signal is not None
    reference = signal["referenceUrl"]
    assert reference is not None
    assert reference.endswith("11111111-1111-1111-1111-111111111111/")
    assert signal["hashes"] == [digest]
