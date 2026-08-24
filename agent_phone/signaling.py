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
    """Encrypt `plaintext` to `recipient_pubkey` and wrap in a signed kind:1059."""
    conv_key = _conversation_key(sender, recipient_pubkey)
    sealed = minipae.nip44_encrypt(plaintext, conv_key)
    return minipae.sign_event(
        KIND_GIFT_WRAP,
        sealed,
        [["p", recipient_pubkey.hex()]],
        sender.seckey,
    )


def unwrap_gift_wrap(gift_wrap_event: dict, recipient: Identity) -> str:
    """Verify a kind:1059 event addressed to us and decrypt its payload.

    Raises ValueError on a wrong kind, a missing/incorrect recipient tag, or a
    bad signature — callers must treat an exception as "do not trust this".
    """
    if gift_wrap_event.get("kind") != KIND_GIFT_WRAP:
        raise ValueError("not a gift-wrap event")

    tags = gift_wrap_event.get("tags", [])
    if ["p", recipient.pubkey_hex] not in tags:
        raise ValueError("gift wrap not addressed to this recipient")

    sender_pubkey = bytes.fromhex(gift_wrap_event["pubkey"])
    event_id_bytes = bytes.fromhex(gift_wrap_event["id"])
    sig = bytes.fromhex(gift_wrap_event["sig"])
    if not minipae.schnorr_verify(event_id_bytes, sender_pubkey, sig):
        raise ValueError("gift-wrap signature does not verify")

    conv_key = _conversation_key(recipient, sender_pubkey)
    return minipae.nip44_decrypt(gift_wrap_event["content"], conv_key)


# -- signal constructors ----------------------------------------------------

def build_offer(caller: Identity, callee_pubkey: bytes, sdp: str, call_id: str | None = None) -> dict:
    signal = Signal(SignalType.OFFER, call_id or uuid.uuid4().hex, sdp=sdp)
    return build_gift_wrap(caller, callee_pubkey, signal.to_json())


def build_answer(callee: Identity, caller_pubkey: bytes, sdp: str, call_id: str) -> dict:
    signal = Signal(SignalType.ANSWER, call_id, sdp=sdp)
    return build_gift_wrap(callee, caller_pubkey, signal.to_json())


def build_ice(agent: Identity, peer_pubkey: bytes, call_id: str, candidate: dict) -> dict:
    signal = Signal(SignalType.ICE, call_id, candidate=candidate)
    return build_gift_wrap(agent, peer_pubkey, signal.to_json())


def build_hangup(agent: Identity, peer_pubkey: bytes, call_id: str, reason: str = "bye") -> dict:
    signal = Signal(SignalType.HANGUP, call_id, reason=reason)
    return build_gift_wrap(agent, peer_pubkey, signal.to_json())


def parse_signal(gift_wrap_event: dict, recipient: Identity) -> Signal:
    """Decrypt + parse an incoming signaling gift wrap into a Signal."""
    return Signal.from_json(unwrap_gift_wrap(gift_wrap_event, recipient))


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
