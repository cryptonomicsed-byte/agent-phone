"""
Presence — heartbeat + relay list (NIP-65 kind:10002).

A periodic signed "I'm alive, here's how to reach me" event. kind:10002 is the
NIP-65 relay-list (outbox model), which doubles as presence: an agent's relay
list tells callers where to subscribe for its heartbeat and signaling.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Callable

import minipae

from .identity import Identity

KIND_RELAY_LIST = 10002
KIND_HEARTBEAT = 10002  # relay list *is* the presence carrier


def build_relay_list(identity: Identity, relays: list[str]) -> dict:
    """NIP-65 relay list (kind:10002) — where the agent can be reached."""
    tags: list[list[str]] = []
    for url in relays:
        tags.append(["r", url])  # read+write relay (no marker = both)
    ev = minipae.sign_event(KIND_RELAY_LIST, "", tags, identity.seckey)
    return ev


def build_heartbeat(identity: Identity, relays: list[str], note: str = "") -> dict:
    """A signed presence heartbeat. Carries reachability + optional status.

    Content is a small JSON object; the relay list tags still carry the
    reachable relays so a caller gets both from one event.
    """
    content = json.dumps({"presence": "online", "note": note, "ts": minipae.time.time()})
    tags: list[list[str]] = [["r", url] for url in relays]
    tags += minipae.label_tags("phone", "presence")
    ev = minipae.sign_event(KIND_HEARTBEAT, content, tags, identity.seckey)
    return ev


@dataclass
class HeartbeatLoop:
    """Async loop that publishes a heartbeat to a relay every `interval_s`.

    The loop itself is transport-agnostic; `publish` is injected so callers
    can use minipae.publish against a live relay or a stub in tests.
    """

    identity: Identity
    relays: list[str]
    interval_s: float = 60.0
    publish: Callable | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.publish is None:
            self.publish = minipae.publish

    async def run(self, stop: asyncio.Event | None = None) -> None:
        stop = stop or asyncio.Event()
        relay = self.relays[0] if self.relays else None
        while not stop.is_set():
            ev = build_heartbeat(self.identity, self.relays)
            if relay is not None:
                try:
                    await self.publish(relay, ev)
                except Exception:
                    # Presence is best-effort; a down relay must not kill the loop.
                    pass
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.interval_s)
            except asyncio.TimeoutError:
                continue
