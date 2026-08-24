"""
Voicemail — store-and-forward messages as engrams + Blossom blob references.

A voicemail is a kind:30174 engram under `mem/phone/voicemail/<id>` whose body
references the audio blob by its Blossom (kind:24242) server + SHA-256 hash.
The engram carries the metadata (caller, duration, timestamp); the audio bytes
live on the Blossom server, addressed by content hash.
"""
from __future__ import annotations

import json

import minipae

from .identity import Identity

VOICEMAIL_SLUG_PREFIX = "mem/phone/voicemail"


def build_voicemail_engram(
    identity: Identity,
    caller_npub: str,
    blob_sha256: str,
    blossom_server: str,
    duration_s: float | None = None,
    transcript: str = "",
) -> dict:
    """Create a signed voicemail engram referencing a Blossom audio blob."""
    slug = f"{VOICEMAIL_SLUG_PREFIX}/{caller_npub[-16:]}-{minipae.time.time_ns() if hasattr(minipae.time, 'time_ns') else int(minipae.time.time()*1e9)}"
    body: dict = {
        "caller": caller_npub,
        "blob_sha256": blob_sha256,
        "blossom": blossom_server,
    }
    if duration_s is not None:
        body["duration_s"] = duration_s
    if transcript:
        body["transcript"] = transcript

    owner_pubkey = identity.pubkey
    ev = minipae.build_event(slug, body, identity.seckey, owner_pubkey)
    ev["tags"] = ev.get("tags", []) + minipae.label_tags("phone", "voicemail")
    # Re-sign after adding labels.
    import secrets
    ev.pop("id", None)
    ev.pop("sig", None)
    ev["id"] = minipae.event_id(ev)
    ev["sig"] = minipae.schnorr_sign(
        bytes.fromhex(ev["id"]), int.from_bytes(identity.seckey, "big"), secrets.token_bytes(32)
    ).hex()
    return ev
