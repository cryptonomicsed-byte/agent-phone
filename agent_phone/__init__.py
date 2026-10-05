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

from .identity import Identity, build_metadata_event, build_binding_engram  # Identity.birth() also available
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

# Reticulum/LXMF is the OFF-GRID fallback transport and is optional at runtime
# (requirements.txt: "Phase 7 (Reticulum/LXMF fallback) — optional at runtime,
# required for the off-grid transport"). Importing it unconditionally meant
# `import agent_phone` failed outright wherever RNS was absent — taking identity,
# signaling, presence, voicemail, NIP-46 and ip_root down with it. Guard it; the
# off-grid path raises only when it is actually used.
try:
    from .reticulum import (
        ReticulumIdentity,
        ReticulumFallback,
        derive_reticulum_hash,
        derive_reticulum_seed,
    )
    HAS_RETICULUM = True
except ImportError:  # RNS not installed — off-grid transport unavailable
    HAS_RETICULUM = False

    class _UnavailableReticulum:  # type: ignore[no-redef]
        def __init__(self, *a, **k):
            raise RuntimeError(
                "Reticulum transport unavailable: `pip install rns lxmf` and run "
                "an rnsd daemon to use the off-grid fallback")

    ReticulumIdentity = _UnavailableReticulum  # type: ignore[assignment]
    ReticulumFallback = _UnavailableReticulum  # type: ignore[assignment]

    def derive_reticulum_hash(*a, **k):  # type: ignore
        raise RuntimeError("Reticulum unavailable: `pip install rns`")

    def derive_reticulum_seed(*a, **k):  # type: ignore
        raise RuntimeError("Reticulum unavailable: `pip install rns`")
from .ip_root import (
    build_ip_root_event,
    build_twin_binding_event,
    build_creation_receipt_event,
    store_ip_root_engram,
    get_ip_root_id,
    seal_splat_ownership,
    KIND_IP_ROOT,
    KIND_CREATION_RECEIPT,
    KIND_TWIN_BINDING,
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
    "build_ip_root_event",
    "build_twin_binding_event",
    "build_creation_receipt_event",
    "store_ip_root_engram",
    "get_ip_root_id",
    "seal_splat_ownership",
    "KIND_IP_ROOT",
    "KIND_CREATION_RECEIPT",
    "KIND_TWIN_BINDING",
]
