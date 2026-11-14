"""
Call signaling over NIP-17 gift wrap.

Offer/answer/ICE/hangup travel as NIP-44-encrypted payloads inside kind:1059
gift-wrap events, so a relay learns only that *some* wrapped event passed —
never who called whom or the SDP. Actual audio/video flows over WebRTC
(out-of-band to Nostr).

The conversation key is ECDH between the two agents' keys, so each side
derives the same shared secret without ever exchanging it:

    sender   : conversation_key(sender.seckey,   recipient.pubkey)
    recipient: conversation_key(recipient.seckey, sender.pubkey)
"""
from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import dataclass
from enum import Enum

import minipae

from .identity import Identity

KIND_GIFT_WRAP = 1059


class SignalType(str, Enum):
    OFFER = "offer"
    ANSWER = "answer"
    ICE = "ice"
    HANGUP = "hangup"


class CallState(str, Enum):
    IDLE = "idle"
    OFFERED = "offered"        # we sent an offer, awaiting answer
    RINGING = "ringing"        # we received an offer, not yet answered
    ANSWERED = "answered"      # we accepted; ICE gathering / connecting
    CONNECTED = "connected"    # media flowing
    ENDED = "ended"


@dataclass
class Signal:
    type: SignalType
    call_id: str
    sdp: str | None = None
    candidate: dict | None = None
    reason: str | None = None

    def to_json(self) -> str:
        payload = {"type": self.type.value, "call_id": self.call_id}
        if self.sdp is not None:
            payload["sdp"] = self.sdp
        if self.candidate is not None:
            payload["candidate"] = self.candidate
        if self.reason is not None:
            payload["reason"] = self.reason
        return json.dumps(payload)

    @classmethod
    def from_json(cls, raw: str) -> "Signal":
        d = json.loads(raw)
        return cls(
            type=SignalType(d["type"]),
            call_id=d["call_id"],
            sdp=d.get("sdp"),
            candidate=d.get("candidate"),
            reason=d.get("reason"),
        )


def _conversation_key(sender: Identity, recipient_pubkey: bytes) -> bytes:
    return minipae.conversation_key(sender.seckey, recipient_pubkey)


def build_gift_wrap(sender: Identity, recipient_pubkey: bytes, plaintext: str) -> dict:
    """Build a proper NIP-17 gift wrap: rumor (kind:14) → seal (kind:13) → wrap (kind:1059).

    The outer gift wrap is signed by a throwaway key so the relay cannot link
    sender to receiver. The seal is signed by the real sender so the recipient
    can verify authenticity after decryption.
    """
    import time
    recipient_hex = recipient_pubkey.hex()

    # Layer 1: RUMOR — kind:14, plaintext DM content, no id/sig fields
    rumor = {
        "kind": 14,
        "content": plaintext,
        "tags": [["p", recipient_hex]],
        "created_at": int(time.time()),
        "pubkey": sender.pubkey_hex,
    }

    # Layer 2: SEAL — kind:13, nip44(rumor) to recipient, signed by sender
    seal_conv_key = minipae.conversation_key(sender.seckey, recipient_pubkey)
    seal = minipae.sign_event(
        13,
        minipae.nip44_encrypt(json.dumps(rumor, separators=(",", ":")), seal_conv_key),
        [],
        sender.seckey,
    )

    # Layer 3: GIFT WRAP — kind:1059, nip44(seal) to recipient, throwaway key
    throwaway = Identity.generate()
    wrap_conv_key = minipae.conversation_key(throwaway.seckey, recipient_pubkey)
    return minipae.sign_event(
        KIND_GIFT_WRAP,
        minipae.nip44_encrypt(json.dumps(seal, separators=(",", ":")), wrap_conv_key),
        [["p", recipient_hex]],
        throwaway.seckey,
    )


def unwrap_gift_wrap(gift_wrap_event: dict, recipient: Identity) -> str:
    """Unwrap a NIP-17 gift wrap and return the plaintext.

    Handles both proper NIP-17 (3-layer: wrap→seal→rumor) and the legacy
    1-layer format (direct payload in the gift wrap). Raises ValueError on
    a wrong kind, bad recipient, or a signature that does not verify.
    """
    if gift_wrap_event.get("kind") != KIND_GIFT_WRAP:
        raise ValueError("not a gift-wrap event")

    tags = gift_wrap_event.get("tags", [])
    if ["p", recipient.pubkey_hex] not in tags:
        raise ValueError("gift wrap not addressed to this recipient")

    wrap_pubkey = bytes.fromhex(gift_wrap_event["pubkey"])
    event_id_bytes = bytes.fromhex(gift_wrap_event["id"])
    sig = bytes.fromhex(gift_wrap_event["sig"])
    if not minipae.schnorr_verify(event_id_bytes, wrap_pubkey, sig):
        raise ValueError("gift-wrap signature does not verify")

    # Decrypt outer layer (throwaway or sender key → recipient)
    outer_conv_key = minipae.conversation_key(recipient.seckey, wrap_pubkey)
    inner_str = minipae.nip44_decrypt(gift_wrap_event["content"], outer_conv_key)

    # Detect NIP-17 3-layer: inner is a signed seal (kind:13)
    try:
        inner = json.loads(inner_str)
    except (json.JSONDecodeError, ValueError):
        return inner_str  # legacy: inner_str is the raw plaintext

    if isinstance(inner, dict) and inner.get("kind") == 13:
        # Verify seal signature (signed by the real sender)
        seal_pubkey = bytes.fromhex(inner["pubkey"])
        seal_id = bytes.fromhex(inner["id"])
        seal_sig = bytes.fromhex(inner["sig"])
        if not minipae.schnorr_verify(seal_id, seal_pubkey, seal_sig):
            raise ValueError("seal signature does not verify")
        seal_conv_key = minipae.conversation_key(recipient.seckey, seal_pubkey)
        rumor_str = minipae.nip44_decrypt(inner["content"], seal_conv_key)
        rumor = json.loads(rumor_str)
        # kind:14 rumor — return the content field; fallback to full rumor string
        if isinstance(rumor, dict) and rumor.get("kind") == 14:
            return rumor["content"]
        return rumor_str

    # Legacy 1-layer: inner parsed as JSON (signal payload) but is not a seal
    return inner_str



def build_signal_wrap(sender: Identity, recipient_pubkey: bytes, plaintext: str) -> dict:
    """Single-layer kind:1059 wrap for browser callers.

    The shipped caller PWA decrypts the gift-wrap content and JSON-parses it
    DIRECTLY as the signal (it has no NIP-17 seal/rumor unwrap). A proper
    NIP-17 3-layer wrap decrypts to a *seal* object, so the caller finds no
    `call_id`, silently drops it, and rings forever. Outbound callee->caller
    signals therefore use the 1-layer form the caller can actually read.
    (The endpoint's unwrap_gift_wrap already accepts both shapes inbound.)
    """
    conv_key = minipae.conversation_key(sender.seckey, recipient_pubkey)
    return minipae.sign_event(
        KIND_GIFT_WRAP,
        minipae.nip44_encrypt(plaintext, conv_key),
        [["p", recipient_pubkey.hex()]],
        sender.seckey,
    )

# -- signal constructors ----------------------------------------------------

def build_offer(caller: Identity, callee_pubkey: bytes, sdp: str, call_id: str | None = None) -> dict:
    signal = Signal(SignalType.OFFER, call_id or uuid.uuid4().hex, sdp=sdp)
    return build_gift_wrap(caller, callee_pubkey, signal.to_json())


def build_answer(callee: Identity, caller_pubkey: bytes, sdp: str, call_id: str) -> dict:
    signal = Signal(SignalType.ANSWER, call_id, sdp=sdp)
    return build_signal_wrap(callee, caller_pubkey, signal.to_json())


def build_ice(agent: Identity, peer_pubkey: bytes, call_id: str, candidate: dict) -> dict:
    signal = Signal(SignalType.ICE, call_id, candidate=candidate)
    return build_signal_wrap(agent, peer_pubkey, signal.to_json())


def build_hangup(agent: Identity, peer_pubkey: bytes, call_id: str, reason: str = "bye") -> dict:
    signal = Signal(SignalType.HANGUP, call_id, reason=reason)
    return build_signal_wrap(agent, peer_pubkey, signal.to_json())


def parse_signal(gift_wrap_event: dict, recipient: Identity) -> Signal:
    """Decrypt + parse an incoming signaling gift wrap into a Signal.

    This does NOT tell you who sent it. Use parse_signal_with_sender for
    anything that routes a reply: the outer pubkey of a NIP-17 wrap is a
    throwaway key.
    """
    return Signal.from_json(unwrap_gift_wrap(gift_wrap_event, recipient))


@dataclass(frozen=True)
class VerifiedSignal:
    signal: Signal
    sender: bytes          # authenticated x-only pubkey of the real sender
    layers: int            # 3 = NIP-17 gift wrap, 1 = legacy single-layer wrap
    event_id: str          # outer event id, for replay de-duplication


def _verify_signed_event(ev: dict, what: str) -> bytes:
    """Recompute the id and check the signature of one event; return its pubkey."""
    try:
        pubkey = bytes.fromhex(ev["pubkey"])
        claimed_id = ev["id"]
        sig = bytes.fromhex(ev["sig"])
        actual_id = minipae.event_id(ev)
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"{what} is malformed: {e}") from None
    if len(pubkey) != 32 or claimed_id != actual_id:
        raise ValueError(f"{what} id does not match its content")
    if not minipae.schnorr_verify(bytes.fromhex(actual_id), pubkey, sig):
        raise ValueError(f"{what} signature does not verify")
    return pubkey


def parse_signal_with_sender(gift_wrap_event: dict, recipient: Identity) -> VerifiedSignal:
    """Decrypt a call-signal gift wrap and return it with its verified sender.

    * three-layer NIP-17 (wrap -> seal -> rumor): the sender is the seal's
      signer, and the rumor must name the same author, otherwise someone could
      re-seal another party's rumor and impersonate them;
    * legacy one-layer wrap: the sender is the outer signer.

    Every signed layer has its id recomputed, so a valid signature cannot be
    carried over to different content. Raises ValueError for anything that
    cannot be authenticated.
    """
    if not isinstance(gift_wrap_event, dict) or gift_wrap_event.get("kind") != KIND_GIFT_WRAP:
        raise ValueError("not a gift-wrap event")
    if ["p", recipient.pubkey_hex] not in gift_wrap_event.get("tags", []):
        raise ValueError("gift wrap not addressed to this recipient")

    wrap_pubkey = _verify_signed_event(gift_wrap_event, "gift wrap")
    try:
        inner_str = minipae.nip44_decrypt(
            gift_wrap_event["content"],
            minipae.conversation_key(recipient.seckey, wrap_pubkey))
        inner = json.loads(inner_str)
    except Exception as e:
        raise ValueError(f"gift wrap does not decrypt to JSON: {e}") from None

    if isinstance(inner, dict) and inner.get("kind") == 13:
        seal_pubkey = _verify_signed_event(inner, "seal")
        try:
            rumor = json.loads(minipae.nip44_decrypt(
                inner["content"], minipae.conversation_key(recipient.seckey, seal_pubkey)))
        except Exception as e:
            raise ValueError(f"seal does not decrypt to JSON: {e}") from None
        if not isinstance(rumor, dict) or rumor.get("kind") != 14:
            raise ValueError("seal does not contain a kind:14 rumor")
        if rumor.get("pubkey") != inner["pubkey"]:
            raise ValueError("rumor author does not match the seal signer")
        payload, sender, layers = rumor.get("content", ""), seal_pubkey, 3
    else:
        payload, sender, layers = inner_str, wrap_pubkey, 1

    try:
        signal = Signal.from_json(payload)
    except Exception as e:
        raise ValueError(f"payload is not a call signal: {e}") from None
    return VerifiedSignal(signal, sender, layers, gift_wrap_event["id"])


class CallSession:
    """Minimal call state machine for one agent.

    Not a full media stack — it tracks the signaling state so the caller can
    hand the negotiated SDP to a WebRTC engine and know when to tear down.
    """

    def __init__(self, identity: Identity):
        self.identity = identity
        self.state = CallState.IDLE
        self.call_id: str | None = None
        self.peer_pubkey: bytes | None = None
        self.local_sdp: str | None = None
        self.remote_sdp: str | None = None

    def offer(self, peer_pubkey: bytes, sdp: str) -> dict:
        if self.state is not CallState.IDLE:
            raise RuntimeError(f"cannot offer from state {self.state}")
        self.call_id = uuid.uuid4().hex
        self.peer_pubkey = peer_pubkey
        self.local_sdp = sdp
        self.state = CallState.OFFERED
        return build_offer(self.identity, peer_pubkey, sdp, self.call_id)

    def on_signal(self, signal: Signal, peer_pubkey: bytes) -> dict | None:
        """Handle an incoming signal; returns an event to send back (or None)."""
        if signal.type is SignalType.OFFER:
            self.call_id = signal.call_id
            self.peer_pubkey = peer_pubkey
            self.remote_sdp = signal.sdp
            self.state = CallState.RINGING
            return None  # caller decides whether to answer

        if signal.call_id != self.call_id:
            raise ValueError("signal for an unknown call")

        if signal.type is SignalType.ANSWER:
            self.remote_sdp = signal.sdp
            self.state = CallState.ANSWERED
            return None
        if signal.type is SignalType.ICE:
            self.state = CallState.ANSWERED
            return None
        if signal.type is SignalType.HANGUP:
            self.state = CallState.ENDED
            return None
        return None

    def answer(self, sdp: str) -> dict:
        if self.state is not CallState.RINGING:
            raise RuntimeError(f"cannot answer from state {self.state}")
        self.local_sdp = sdp
        self.state = CallState.ANSWERED
        assert self.peer_pubkey is not None and self.call_id is not None
        return build_answer(self.identity, self.peer_pubkey, sdp, self.call_id)

    def hangup(self, reason: str = "bye") -> dict:
        if self.state in (CallState.IDLE, CallState.ENDED):
            raise RuntimeError("no active call to hang up")
        self.state = CallState.ENDED
        assert self.peer_pubkey is not None and self.call_id is not None
        return build_hangup(self.identity, self.peer_pubkey, self.call_id, reason)
