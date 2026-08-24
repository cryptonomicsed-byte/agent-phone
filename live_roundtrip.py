"""Live end-to-end round-trip against a real Nostr relay.

Proves the agent-phone stack works against live infrastructure (not just unit
tests): publish a heartbeat + a gift-wrapped call offer to relay.damus.io, read
them back, and decrypt the offer with the callee's key.

Run:
    python3 live_roundtrip.py [relay_url]   # default wss://relay.damus.io
"""
from __future__ import annotations

import asyncio
import sys

import minipae

from agent_phone import (
    Identity,
    SignalType,
    build_heartbeat,
    build_offer,
    parse_signal,
)

RELAY = sys.argv[1] if len(sys.argv) > 1 else "wss://relay.damus.io"


async def main() -> int:
    caller = Identity.generate()
    callee = Identity.generate()

    print(f"relay        : {RELAY}")
    print(f"caller npub  : {caller.npub}")
    print(f"callee npub  : {callee.npub}")
    print()

    # 1. Publish a heartbeat (kind:10002) from the caller.
    hb = build_heartbeat(caller, [RELAY], note="live-roundtrip")
    print(f"[1] publishing heartbeat (kind:{hb['kind']}, id:{hb['id'][:8]}…)")
    ok = await minipae.publish(RELAY, hb)
    print(f"    relay accepted: {ok.get('ok')} ({ok.get('message', '')})")
    assert ok.get("ok"), "heartbeat was rejected by the relay"

    # 2. Publish a gift-wrapped offer from caller to callee.
    offer = build_offer(caller, callee.pubkey, "v=0\r\nsdp=live-roundtrip-offer")
    print(f"[2] publishing offer (kind:{offer['kind']}, id:{offer['id'][:8]}…, to:{callee.npub[:12]}…)")
    ok = await minipae.publish(RELAY, offer)
    print(f"    relay accepted: {ok.get('ok')} ({ok.get('message', '')})")
    assert ok.get("ok"), "offer was rejected by the relay"

    # 3. Give the relay a moment, then read the heartbeat back.
    await asyncio.sleep(2)
    print("[3] reading heartbeat back via NIP-65 relay-list fetch…")
    relay_list = await minipae.fetch_relay_list(RELAY, caller.pubkey_hex)
    assert relay_list, "heartbeat (kind:10002) was not found on the relay"
    urls = [u for u, _ in relay_list]
    print(f"    found relay list: {urls}")
    assert RELAY in urls, "heartbeat relay list did not contain our relay"

    # 4. Read the offer back and decrypt it with the callee's key.
    print("[4] reading the offer back (query kind:1059 by caller)…")
    events = await minipae.query_authenticated(
        RELAY, [caller.pubkey_hex], callee.seckey, kinds=[1059]
    )
    assert events, "no gift-wrap events returned by the relay"
    print(f"    got {len(events)} kind:1059 event(s)")

    sig = parse_signal(events[0], callee)
    assert sig.type is SignalType.OFFER, f"expected offer, got {sig.type}"
    assert sig.sdp == "v=0\r\nsdp=live-roundtrip-offer", "SDP did not round-trip"
    print(f"    decrypted offer: type={sig.type.value}, call_id={sig.call_id[:8]}…, sdp={sig.sdp!r}")
    print()
    print("✅ LIVE ROUND-TRIP PASSED — heartbeat published+read, offer published+decrypted")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
