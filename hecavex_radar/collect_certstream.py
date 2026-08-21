from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import time
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from websockets.asyncio.client import ClientConnection, connect

from .brands import load_brand_registry, score_domain
from .candidates import CandidateArchiveWriter, candidate_from_match
from .certstream import domains_from_message
from .models import CertStreamCandidate

MAXIMUM_MESSAGE_BYTES = 1024 * 1024


def _enabled(value: str | None) -> bool:
    return bool(value and value.strip().lower() == "true")


def _bounded_integer(value: str | None, fallback: int, minimum: int, maximum: int) -> int:
    if not value or not value.strip():
        return fallback
    try:
        parsed = int(value)
    except ValueError:
        return fallback
    return min(maximum, max(minimum, parsed))


def _websocket_url(value: str | None, allow_insecure: bool) -> str:
    url = value.strip() if value and value.strip() else "wss://certstream.calidog.io/"
    parsed = urlsplit(url)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "wss" and not (parsed.scheme == "ws" and (local or allow_insecure)):
        raise ValueError(
            "CERTSTREAM_URL must use WSS (set CERTSTREAM_ALLOW_INSECURE_WS=true only for a trusted private network)."
        )
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("CERTSTREAM_URL must not contain credentials.")
    return url


async def _receive_or_stop(websocket: ClientConnection, stop: asyncio.Event, timeout: float) -> str | bytes | None:
    receive_task = asyncio.create_task(websocket.recv())
    stop_task = asyncio.create_task(stop.wait())
    done, pending = await asyncio.wait({receive_task, stop_task}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    if not done:
        await asyncio.gather(*pending, return_exceptions=True)
        raise TimeoutError
    if stop_task in done and stop_task.result():
        receive_task.cancel()
        await asyncio.gather(receive_task, return_exceptions=True)
        return None
    stop_task.cancel()
    await asyncio.gather(stop_task, return_exceptions=True)
    return receive_task.result()


async def collect() -> int:
    registry = load_brand_registry()
    url = _websocket_url(os.environ.get("CERTSTREAM_URL"), _enabled(os.environ.get("CERTSTREAM_ALLOW_INSECURE_WS")))
    duration_seconds = _bounded_integer(os.environ.get("CERTSTREAM_DURATION_SECONDS"), 0, 0, 86_400)
    flush_seconds = _bounded_integer(os.environ.get("CERTSTREAM_FLUSH_SECONDS"), 15, 5, 300)
    idle_seconds = _bounded_integer(os.environ.get("CERTSTREAM_IDLE_SECONDS"), 90, 30, 600)
    minimum_confidence = _bounded_integer(os.environ.get("CERTSTREAM_MIN_CONFIDENCE"), 65, 1, 100)
    require_messages = _enabled(os.environ.get("CERTSTREAM_REQUIRE_MESSAGES"))
    archive_root = os.environ.get("CERTSTREAM_ARCHIVE_ROOT", "").strip() or "data/candidates"
    writer = CandidateArchiveWriter(archive_root)
    pending: dict[str, CertStreamCandidate] = {}
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    def request_stop(*_arguments: object) -> None:
        loop.call_soon_threadsafe(stop.set)

    for interrupt in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(interrupt, stop.set)
        except NotImplementedError:
            signal.signal(interrupt, request_stop)

    messages = 0
    domains_checked = 0
    matched = 0
    saved = 0
    retry_seconds = 1.0
    started = time.monotonic()
    deadline = started + duration_seconds if duration_seconds else float("inf")
    last_flush = started
    last_stats = started

    def flush() -> None:
        nonlocal saved, last_flush
        batch = list(pending.values())
        pending.clear()
        try:
            saved += writer.append(batch)
            last_flush = time.monotonic()
        except Exception:
            pending.update((candidate["id"], candidate) for candidate in batch)
            raise

    mode = "continuous" if duration_seconds == 0 else f"{duration_seconds}s bounded"
    print(f"CertStream collector started with {len(registry.entries)} public brand entries ({mode} mode).", flush=True)

    while not stop.is_set() and time.monotonic() < deadline:
        try:
            async with connect(
                url,
                open_timeout=15,
                max_size=MAXIMUM_MESSAGE_BYTES,
                ping_interval=30,
                ping_timeout=20,
                close_timeout=10,
            ) as websocket:
                retry_seconds = 1.0
                print("CertStream connection established.", flush=True)
                while not stop.is_set() and time.monotonic() < deadline:
                    remaining = deadline - time.monotonic()
                    timeout = min(float(idle_seconds), remaining)
                    try:
                        raw = await _receive_or_stop(websocket, stop, timeout)
                    except TimeoutError:
                        if time.monotonic() >= deadline:
                            break
                        print(
                            f"CertStream connection was idle for {idle_seconds}s; reconnecting.",
                            file=sys.stderr,
                            flush=True,
                        )
                        break
                    if raw is None:
                        break
                    body = raw.decode("utf-8", errors="strict") if isinstance(raw, bytes) else raw
                    if len(body.encode("utf-8")) > MAXIMUM_MESSAGE_BYTES:
                        continue
                    try:
                        payload: Any = json.loads(body)
                    except json.JSONDecodeError:
                        continue
                    messages += 1
                    observed_at = datetime.now(UTC)
                    for candidate_domain in domains_from_message(payload):
                        domains_checked += 1
                        match = score_domain(candidate_domain, registry)
                        if not match or match.confidence < minimum_confidence:
                            continue
                        matched += 1
                        candidate = candidate_from_match(match, observed_at)
                        pending.setdefault(candidate["id"], candidate)
                    current = time.monotonic()
                    if len(pending) >= 5_000 or current - last_flush >= flush_seconds:
                        flush()
                    if current - last_stats >= 60:
                        print(
                            f"CertStream: {messages} messages, {domains_checked} domains checked, "
                            f"{matched} candidates matched, {saved} new records saved.",
                            flush=True,
                        )
                        last_stats = current
        except Exception as error:
            message = str(error).splitlines()[0] if str(error) else type(error).__name__
            print(f"CertStream connection unavailable: {message}", file=sys.stderr, flush=True)

        if stop.is_set() or time.monotonic() >= deadline:
            break
        wait_seconds = min(retry_seconds, max(0.0, deadline - time.monotonic()))
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=wait_seconds)
        retry_seconds = min(30.0, retry_seconds * 2)

    flush()
    print(
        f"CertStream collector stopped: {messages} messages, {domains_checked} domains checked, "
        f"{matched} candidates matched, {saved} new records saved.",
        flush=True,
    )
    if require_messages and messages == 0:
        raise RuntimeError("The CertStream endpoint produced no messages during the collection window.")
    return saved


def main() -> int:
    try:
        asyncio.run(collect())
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"CertStream collector failed: {error}", file=sys.stderr)
        return 1


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
