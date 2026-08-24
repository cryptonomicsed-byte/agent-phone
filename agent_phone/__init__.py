"""
agent-phone — sovereign, verifiable AI-agent communications stack.

Nostr-native identity (npub root), NIP-17 gift-wrapped call signaling,
heartbeat presence, NIP-46 transport-key signing, and Blossom voicemail —
built on top of minipae (BIP-340 + NIP-44 v2 + NIP-AE engrams).

Nautilus TEE attestation is the only piece that stays on Sui and remains
deferred until AWS Nitro hardware is available (see README § Phase 1).

The brain runs as an ordinary process for now; the wire format is identical
whether the responses come from a TEE or not, so the trust upgrade slots in
without changing the telecom stack.
"""

__version__ = "0.1.0"

from .identity import Identity, build_metadata_event, build_binding_engram
from .signaling import (
    SignalType,
    CallState,
    build_gift_wrap,
    unwrap_gift_wrap,
    build_offer,
    build_answer,
    build_ice,
    build_hangup,
    parse_signal,
)
from .presence import build_relay_list, build_heartbeat, HeartbeatLoop
from .voicemail import build_voicemail_engram
from .nip46 import PhoneSigner
from .reticulum import (
    ReticulumIdentity,
    ReticulumFallback,
    derive_reticulum_hash,
    derive_reticulum_seed,
)

__all__ = [
    "Identity",
    "build_metadata_event",
    "build_binding_engram",
    "SignalType",
    "CallState",
    "build_gift_wrap",
    "unwrap_gift_wrap",
    "build_offer",
    "build_answer",
    "build_ice",
    "build_hangup",
    "parse_signal",
    "build_relay_list",
    "build_heartbeat",
    "HeartbeatLoop",
    "build_voicemail_engram",
    "PhoneSigner",
    "ReticulumIdentity",
    "ReticulumFallback",
    "derive_reticulum_hash",
    "derive_reticulum_seed",
]
