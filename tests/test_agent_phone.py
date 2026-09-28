"""Unit tests for the agent-phone sovereign telecom stack.

These exercise the pure logic (identity, binding, gift-wrapped signaling,
voicemail, heartbeat, IP root) with two ephemeral identities — no relay needed.
"""
import hashlib
import json

import pytest

import minipae
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
    build_ip_root_event,
    build_twin_binding_event,
    build_creation_receipt_event,
    seal_splat_ownership,
    KIND_IP_ROOT,
    KIND_CREATION_RECEIPT,
    KIND_TWIN_BINDING,
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


# ── IP Root (kind:31900) ──────────────────────────────────────────────────────

def test_ip_root_event_structure():
    a = Identity.generate()
    ev = build_ip_root_event(a, display_name="test-agent", created_at=1_700_000_000)
    assert ev["kind"] == KIND_IP_ROOT
    assert ev["pubkey"] == a.pubkey_hex
    # d-tag must be the agent's own pubkey hex
    tags = {t[0]: t[1] for t in ev["tags"] if len(t) >= 2}
    assert tags["d"] == a.pubkey_hex
    assert tags["license"] == "cc-by-4.0"
    content = json.loads(ev["content"])
    assert content["display_name"] == "test-agent"
    assert content["framework"] == "omo-koda2"


def test_ip_root_event_id_deterministic():
    a = Identity.generate()
    ev1 = build_ip_root_event(a, "agent", created_at=1_700_000_000)
    ev2 = build_ip_root_event(a, "agent", created_at=1_700_000_000)
    # Same inputs → same event id (sig differs due to random aux, id is deterministic)
    assert ev1["id"] == ev2["id"]


def test_ip_root_event_id_matches_nip01():
    """NIP-01: event id = sha256([0, pubkey, created_at, kind, tags, content])."""
    a = Identity.generate()
    ev = build_ip_root_event(a, "agent", created_at=1_700_000_000)
    serial = json.dumps(
        [0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    expected = hashlib.sha256(serial.encode()).hexdigest()
    assert ev["id"] == expected


def test_ip_root_sig_verifies():
    a = Identity.generate()
    ev = build_ip_root_event(a, "agent")
    assert minipae.schnorr_verify(
        bytes.fromhex(ev["id"]),
        a.pubkey,
        bytes.fromhex(ev["sig"]),
    )


def test_ip_root_optional_fields():
    a = Identity.generate()
    ev = build_ip_root_event(
        a, "sovereign",
        owner_npub="npub1abc",
        soul_pubkey="deadbeef" * 8,
        dao_id="dao-xyz",
        notes="test note",
    )
    tag_keys = [t[0] for t in ev["tags"]]
    assert "owner" in tag_keys
    assert "soul" in tag_keys
    assert "dao" in tag_keys
    content = json.loads(ev["content"])
    assert content["notes"] == "test note"


# ── Twin Binding (kind:1903) ──────────────────────────────────────────────────

def test_twin_binding_structure():
    a = Identity.generate()
    ev = build_twin_binding_event(
        a,
        twin_id="twin-abc123",
        scene_receipt_id="receipt-xyz",
        f1_score=0.9812,
        created_at=1_700_000_001,
    )
    assert ev["kind"] == KIND_TWIN_BINDING
    assert ev["pubkey"] == a.pubkey_hex
    tags = {t[0]: t[1] for t in ev["tags"] if len(t) >= 2}
    assert tags["ip_root"] == a.pubkey_hex
    assert tags["sim_id"] == "twin-abc123"
    assert tags["twin_kind"] == "gaussian-splat-1to1"
    assert tags["fidelity"] == "0.9812"
    # osovm_op tag: ["osovm_op", "RECEIPT", receipt_id]
    osovm = next(t for t in ev["tags"] if t[0] == "osovm_op")
    assert osovm[1] == "RECEIPT"
    assert osovm[2] == "receipt-xyz"


def test_twin_binding_sig_verifies():
    a = Identity.generate()
    ev = build_twin_binding_event(a, "twin-1", "rcpt-1")
    assert minipae.schnorr_verify(
        bytes.fromhex(ev["id"]), a.pubkey, bytes.fromhex(ev["sig"])
    )


def test_twin_binding_no_fidelity():
    a = Identity.generate()
    ev = build_twin_binding_event(a, "twin-1", "rcpt-1")
    assert not any(t[0] == "fidelity" for t in ev["tags"])


# ── Creation Receipt (kind:1901) ──────────────────────────────────────────────

def test_creation_receipt_structure():
    a = Identity.generate()
    splat = b"fake-splat-bytes"
    sha = hashlib.sha256(splat).hexdigest()
    ev = build_creation_receipt_event(
        a,
        content_sha256   = sha,
        scene_receipt_id = "scene-001",
        twin_binding_id  = "binding-event-id",
        title            = "My Splat",
        created_at       = 1_700_000_002,
    )
    assert ev["kind"] == KIND_CREATION_RECEIPT
    assert ev["pubkey"] == a.pubkey_hex
    tags = {t[0]: t[1] for t in ev["tags"] if len(t) >= 2}
    assert tags["ip_root"] == a.pubkey_hex
    assert tags["x"] == sha
    assert tags["m"] == "model/splat+ply"
    assert tags["L"] == "license"
    assert tags["twin"] == "binding-event-id"
    content = json.loads(ev["content"])
    assert content["title"] == "My Splat"


def test_creation_receipt_sig_verifies():
    a = Identity.generate()
    ev = build_creation_receipt_event(
        a, "abc" * 21 + "d", "scene-1", "twin-1", "Title"
    )
    assert minipae.schnorr_verify(
        bytes.fromhex(ev["id"]), a.pubkey, bytes.fromhex(ev["sig"])
    )


def test_creation_receipt_no_twin():
    a = Identity.generate()
    ev = build_creation_receipt_event(a, "sha256abc", "scene-1", None, "Title")
    assert not any(t[0] == "twin" for t in ev["tags"])


# ── seal_splat_ownership ──────────────────────────────────────────────────────

def test_seal_splat_ownership_returns_three_events():
    a = Identity.generate()
    splat = b"\x00\x01\x02gaussian"
    ip_root, twin_binding, creation_receipt = seal_splat_ownership(
        a, "twin-42", "scene-42", splat, f1_score=0.95, title="Scene 42"
    )
    assert ip_root["kind"] == KIND_IP_ROOT
    assert twin_binding["kind"] == KIND_TWIN_BINDING
    assert creation_receipt["kind"] == KIND_CREATION_RECEIPT


def test_seal_splat_timestamps_ordered():
    a = Identity.generate()
    ip_root, twin, receipt = seal_splat_ownership(
        a, "twin-1", "scene-1", b"data", None, "Test"
    )
    assert twin["created_at"] == ip_root["created_at"] + 1
    assert receipt["created_at"] == twin["created_at"] + 1


def test_seal_splat_twin_links_receipt():
    """Creation receipt must reference twin binding event id."""
    a = Identity.generate()
    _, twin, receipt = seal_splat_ownership(a, "t", "s", b"x", None, "T")
    twin_tag = next(t for t in receipt["tags"] if t[0] == "twin")
    assert twin_tag[1] == twin["id"]


def test_seal_splat_content_hash():
    """x tag in creation receipt must be sha256 of splat bytes."""
    a = Identity.generate()
    splat = b"sovereign-gaussian-splat"
    _, _, receipt = seal_splat_ownership(a, "t", "s", splat, None, "T")
    x_tag = next(t for t in receipt["tags"] if t[0] == "x")
    assert x_tag[1] == hashlib.sha256(splat).hexdigest()


def test_seal_splat_all_sigs_verify():
    a = Identity.generate()
    events = seal_splat_ownership(a, "t", "s", b"data", 0.88, "T")
    for ev in events:
        assert minipae.schnorr_verify(
            bytes.fromhex(ev["id"]), a.pubkey, bytes.fromhex(ev["sig"])
        )


# ── engram round-trip (offline, no relay) ────────────────────────────────────

def test_ip_root_engram_dtag_derivation():
    """d-tag for mem/ip/root must match minipae.d_tag(slug, kc)."""
    a = Identity.generate()
    from agent_phone.ip_root import IP_ROOT_SLUG
    import minipae as mp
    kc = mp.conversation_key(a.seckey, a.pubkey)
    expected = mp.d_tag(IP_ROOT_SLUG, kc)
    ev = mp.build_event(IP_ROOT_SLUG, {"test": 1}, a.seckey, a.pubkey)
    actual = next(t[1] for t in ev["tags"] if t[0] == "d")
    assert actual == expected


def test_identity_birth_returns_ip_root():
    """Identity.birth() must return (identity, ip_root_event) coherently."""
    identity, ip_root = Identity.birth("my-agent")
    assert isinstance(identity, Identity)
    assert ip_root["kind"] == KIND_IP_ROOT
    assert ip_root["pubkey"] == identity.pubkey_hex
    # d-tag is the agent's own pubkey
    tags = {t[0]: t[1] for t in ip_root["tags"] if len(t) >= 2}
    assert tags["d"] == identity.pubkey_hex
    content = json.loads(ip_root["content"])
    assert content["display_name"] == "my-agent"


def test_identity_birth_sig_verifies():
    identity, ip_root = Identity.birth()
    assert minipae.schnorr_verify(
        bytes.fromhex(ip_root["id"]), identity.pubkey, bytes.fromhex(ip_root["sig"])
    )


def test_identity_birth_with_owner_npub():
    identity, ip_root = Identity.birth("agent", owner_npub="npub1test")
    tag_keys = [t[0] for t in ip_root["tags"]]
    assert "owner" in tag_keys


def test_ip_root_engram_body_roundtrip():
    """build_event / decode_body must round-trip ip root body."""
    from agent_phone.ip_root import IP_ROOT_SLUG
    import minipae as mp
    a = Identity.generate()
    ip_root_ev = build_ip_root_event(a, "agent")
    body = {
        "ip_root_event_id": ip_root_ev["id"],
        "pubkey":           ip_root_ev["pubkey"],
        "kind":             ip_root_ev["kind"],
        "created_at":       ip_root_ev["created_at"],
    }
    kc = mp.conversation_key(a.seckey, a.pubkey)
    engram_ev = mp.build_event(IP_ROOT_SLUG, body, a.seckey, a.pubkey)
    decoded = mp.decode_body(engram_ev, kc)
    assert decoded["ip_root_event_id"] == ip_root_ev["id"]
    assert decoded["pubkey"] == a.pubkey_hex
