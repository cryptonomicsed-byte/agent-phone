"""
Reticulum + LXMF fallback transport (Phase 7).

The resilience layer: when Nostr relays are unreachable, the agent stays
reachable over Reticulum — a transport-agnostic mesh (LoRa/RNode, packet
radio, TCP, I2P, anything) — with LXMF providing delay/disruption-tolerant,
encrypted, store-and-forward messaging via Propagation Nodes.

This is the "the call can't get through, but the message will eventually
arrive" layer — the agent's answering machine.

Identity is derived deterministically from the agent's secp256k1 seckey
(HKDF -> 64 bytes -> RNS Ed25519+X25519 identity), so the same agent seed
always yields the same Reticulum identity and the same `reticulum_hash` in
the binding record. One seed, one identity, every transport.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
from typing import Callable, Optional

import RNS

# HKDF domain separation for the Reticulum leg (do not reuse elsewhere).
_RETICULUM_SALT = b"AGENT-PHONE/RETICULUM/v1"
_RETICULUM_INFO = b"reticulum-identity"
# RNS Identity.KEYSIZE is 512 bits = 64 bytes (32 Ed25519 sig + 32 X25519 enc).
_RETICULUM_KEY_BYTES = 64


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256, stdlib only."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_reticulum_seed(agent_seckey: bytes) -> bytes:
    """Deterministically expand the agent seckey into a 64-byte RNS key."""
    if len(agent_seckey) != 32:
        raise ValueError("agent seckey must be 32 bytes")
    return _hkdf(agent_seckey, _RETICULUM_SALT, _RETICULUM_INFO, _RETICULUM_KEY_BYTES)


def derive_reticulum_hash(agent_seckey: bytes) -> str:
    """The Reticulum destination hash for the binding record (no RNS object)."""
    return RNS.Identity.from_bytes(derive_reticulum_seed(agent_seckey)).hexhash


class ReticulumIdentity:
    """A deterministic RNS identity rooted in the agent's seckey."""

    def __init__(self, agent_seckey: bytes):
        self._identity = RNS.Identity.from_bytes(derive_reticulum_seed(agent_seckey))

    @property
    def rns_identity(self) -> "RNS.Identity":
        return self._identity

    @property
    def reticulum_hash(self) -> str:
        return self._identity.hexhash

    def destination(self, app_name: str = "agent-phone", direction: int = None) -> "RNS.Destination":
        direction = direction if direction is not None else RNS.Destination.IN
        return RNS.Destination(self._identity, direction, RNS.Destination.SINGLE, app_name)


class ReticulumFallback:
    """LXMF store-and-forward fallback: async messaging when Nostr is down.

    Requires `pip install lxmf` and a running RNS daemon (`rnsd`) with at
    least one transport configured. Importing this class without LXMF
    installed raises at construction time, not import time.
    """

    def __init__(
        self,
        agent_seckey: bytes,
        storage_path: Optional[str] = None,
        autopeer: bool = False,
        message_callback: Optional[Callable[[dict], None]] = None,
    ):
        try:
            import LXMF  # noqa: F401 — lazy so RNS-only use never requires it
        except ImportError as e:
            raise RuntimeError(
                "LXMF is not installed — install it with `pip install lxmf` to "
                "use the Reticulum fallback transport"
            ) from e

        self._identity = RNS.Identity.from_bytes(derive_reticulum_seed(agent_seckey))
        self._router = LXMF.LXMRouter(
            storagepath=storage_path or os.path.join(tempfile.gettempdir(), "agent-phone-lxmf"),
            identity=self._identity,
            autopeer=autopeer,
        )
        self._router.register_delivery_callback(self._on_delivery)
        self._message_callback = message_callback
        # LXMF's app name is "lxmf" (RNS forbids dots); "delivery" is an aspect.
        self._source = RNS.Destination(
            self._identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery"
        )

    @property
    def reticulum_hash(self) -> str:
        return self._identity.hexhash

    def announce(self) -> None:
        """Register this agent with LXMF propagation nodes (store-and-forward)."""
        self._router.announce(self._identity.hash)

    def send_message(self, recipient_hexhash: str, content: str, title: str = "agent-phone") -> dict:
        """Send a delay-tolerant message to a peer by Reticulum destination hash.

        Returns a dict with the message hash and delivery method. Delivery is
        best-effort; a peer that is offline will receive it when it reappears,
        provided a propagation node holds the path.
        """
        import LXMF

        recipient_identity = RNS.Identity.recall(recipient_hexhash)
        if recipient_identity is None:
            # No local identity record — rely on a propagation node. Tell the
            # router to build a path to the hash, then retry the recall.
            self._router.announce(bytes.fromhex(recipient_hexhash))
            recipient_identity = RNS.Identity.recall(recipient_hexhash)
            if recipient_identity is None:
                raise RuntimeError(
                    f"no path to {recipient_hexhash} and no propagation node knows it yet"
                )

        destination = RNS.Destination(
            recipient_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery"
        )
        message = LXMF.LXMessage(destination, self._source, content, title=title)
        self._router.handle_outbound(message)
        return {
            "hash": message.hash.hex() if isinstance(message.hash, bytes) else str(message.hash),
            "recipient": recipient_hexhash,
            "method": "lxmf",
        }

    def _on_delivery(self, message) -> None:
        """LXMF delivery callback — surface received messages to the caller."""
        if self._message_callback is None:
            return
        content = message.content.decode("utf-8") if isinstance(message.content, bytes) else message.content
        self._message_callback(
            {
                "content": content,
                "title": getattr(message, "title", None),
                "source_hash": getattr(message, "source_hash", None),
                "fields": getattr(message, "fields", None),
            }
        )
