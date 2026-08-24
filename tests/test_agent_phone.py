"""Unit tests for the agent-phone sovereign telecom stack.

These exercise the pure logic (identity, binding, gift-wrapped signaling,
voicemail, heartbeat) with two ephemeral identities — no relay needed.
"""
import json

import pytest

from agent_phone import (
    Identity,
    CallState,
    SignalType,
    build_answer,
    build_binding_engram,
    build_heartbeat,
    build_metadata_event,
    build_offer,
    build_voicemail_engram,
    parse_signal,
)
from agent_phone.signaling import CallSession


def test_identity_generate_roundtrip():
    a = Identity.generate()
    assert len(a.seckey) == 32
    assert a.nsec.startswith("nsec1")
    assert a.npub.startswith("npub1")
    # Round-trip through nsec encoding.
    b = Identity.from_nsec(a.nsec)
    assert b.seckey == a.seckey
    assert b.npub == a.npub


def test_metadata_event():
    a = Identity.generate()
    ev = build_metadata_event(a, "bino-agent", nip05="agent@bino.example")
    assert ev["kind"] == 0
    assert ev["pubkey"] == a.pubkey_hex
    content = json.loads(ev["content"])
    assert content["name"] == "bino-agent"
    assert content["nip05"] == "agent@bino.example"


def test_binding_engram():
    a = Identity.generate()
    ev = build_binding_engram(a, nip05="a@example", sui_address="0xabc")
    assert ev["kind"] == 30174
    assert ev["pubkey"] == a.pubkey_hex
    # NIP-32 labels present.
    flat = [" ".join(t) for t in ev["tags"]]
    assert any("phone" in f and "binding" in f for f in flat)


def test_gift_wrap_signaling_roundtrip():
    alice = Identity.generate()
    bob = Identity.generate()

    # Alice offers a call to Bob.
    offer_ev = build_offer(alice, bob.pubkey, "alice-sdp-offer")
    assert offer_ev["kind"] == 1059
    assert ["p", bob.pubkey_hex] in offer_ev["tags"]

    # Bob decrypts the offer.
    offer = parse_signal(offer_ev, bob)
    assert offer.type is SignalType.OFFER
    assert offer.sdp == "alice-sdp-offer"

    # Bob answers back to Alice.
    answer_ev = build_answer(bob, alice.pubkey, "bob-sdp-answer", offer.call_id)
    answer = parse_signal(answer_ev, alice)
    assert answer.type is SignalType.ANSWER
    assert answer.sdp == "bob-sdp-answer"
    assert answer.call_id == offer.call_id


def test_gift_wrap_rejects_wrong_recipient():
    alice = Identity.generate()
    bob = Identity.generate()
    eve = Identity.generate()
    offer_ev = build_offer(alice, bob.pubkey, "sdp")
    with pytest.raises(ValueError):
        parse_signal(offer_ev, eve)  # not addressed to eve


def test_call_session_state_machine():
    alice = Identity.generate()
    bob = Identity.generate()
    alice_session = CallSession(alice)
    bob_session = CallSession(bob)

    # Alice offers.
    offer_ev = alice_session.offer(bob.pubkey, "alice-sdp")
    assert alice_session.state is CallState.OFFERED

    # Bob receives the offer -> ringing.
    offer_sig = parse_signal(offer_ev, bob)
    bob_session.on_signal(offer_sig, alice.pubkey)
    assert bob_session.state is CallState.RINGING

    # Bob answers.
    answer_ev = bob_session.answer("bob-sdp")
    assert bob_session.state is CallState.ANSWERED

    # Alice receives the answer.
    answer_sig = parse_signal(answer_ev, alice)
    alice_session.on_signal(answer_sig, bob.pubkey)
    assert alice_session.state is CallState.ANSWERED

    # Bob hangs up; Alice sees the hangup.
    hangup_ev = bob_session.hangup("done")
    hangup_sig = parse_signal(hangup_ev, alice)
    alice_session.on_signal(hangup_sig, bob.pubkey)
    assert alice_session.state is CallState.ENDED


def test_voicemail_engram():
    a = Identity.generate()
    ev = build_voicemail_engram(a, "npub1caller", "deadbeef" * 8, "https://blossom.example", duration_s=12.5)
    assert ev["kind"] == 30174
    assert ev["pubkey"] == a.pubkey_hex


def test_heartbeat():
    a = Identity.generate()
    ev = build_heartbeat(a, ["wss://relay.damus.io"], note="test")
    assert ev["kind"] == 10002
    assert ["r", "wss://relay.damus.io"] in ev["tags"]
    content = json.loads(ev["content"])
    assert content["presence"] == "online"
