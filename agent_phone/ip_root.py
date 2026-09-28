"""
IP Root birth flow for agent-phone.

Publishes kind:31900 (IP Root) to Nostr at agent identity birth.
Uses minipae for BIP-340 signing — minipae already implements the full
secp256k1 Schnorr stack (BIP-340, NIP-44) that Nostr requires.

The IP Root:
  - Uses the agent's own npub (from minipae identity) as the `d` tag
  - Establishes provenance ownership for all future Creation Receipts (1901)
  - Stores ip_root_id in mem/ip/root engram via minipae
  - Is the `ip_root_id` field referenced in sovereign-runtime Principal

Schema: https://github.com/cryptonomicsed-byte/ip-layer/blob/main/schemas/ip_root.md
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Optional

import minipae

KIND_IP_ROOT          = 31900
KIND_CREATION_RECEIPT = 1901
KIND_TWIN_BINDING     = 1903
KIND_ATTESTATION      = 1902

IP_ROOT_SLUG = "mem/ip/root"


# ── helpers ───────────────────────────────────────────────────────────────────

def _sign(event_id_hex: str, seckey: bytes) -> str:
    """BIP-340 Schnorr sign an event id hex → sig hex."""
    return minipae.schnorr_sign(
        bytes.fromhex(event_id_hex),
        int.from_bytes(seckey, "big"),
        secrets.token_bytes(32),
    ).hex()


def _build_and_sign(
    pubkey_hex: str,
    created_at: int,
    kind: int,
    tags: list,
    content: str,
    seckey: bytes,
) -> dict:
    """Assemble a signed Nostr event (NIP-01 canonical id + BIP-340 sig)."""
    serial = json.dumps(
        [0, pubkey_hex, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    event_id = hashlib.sha256(serial.encode()).hexdigest()
    return {
        "id":         event_id,
        "pubkey":     pubkey_hex,
        "created_at": created_at,
        "kind":       kind,
        "tags":       tags,
        "content":    content,
        "sig":        _sign(event_id, seckey),
    }


# ── Event builders ────────────────────────────────────────────────────────────

def build_ip_root_event(
    identity: "minipae.Identity | object",
    display_name: str,
    framework: str = "omo-koda2",
    license: str = "cc-by-4.0",
    owner_npub: Optional[str] = None,
    soul_pubkey: Optional[str] = None,
    dao_id: Optional[str] = None,
    notes: Optional[str] = None,
    created_at: Optional[int] = None,
) -> dict:
    """
    Build and sign a kind:31900 IP Root event.
    The agent's own pubkey_hex is used as the `d` tag (stable addressable id).
    """
    if created_at is None:
        created_at = int(time.time())

    pubkey_hex = identity.pubkey.hex()

    tags: list = [
        ["d",       pubkey_hex],
        ["license", license],
    ]
    if owner_npub:
        tags.append(["owner", owner_npub])
    if soul_pubkey:
        tags.append(["soul", soul_pubkey])
    if dao_id:
        tags.append(["dao", dao_id])

    content = json.dumps({
        "display_name": display_name,
        "framework":    framework,
        "notes":        notes or "",
    })

    return _build_and_sign(pubkey_hex, created_at, KIND_IP_ROOT, tags, content, identity.seckey)


def build_twin_binding_event(
    identity:         "object",
    twin_id:          str,
    scene_receipt_id: str,
    f1_score:         Optional[float] = None,
    notes:            str = "",
    created_at:       Optional[int] = None,
) -> dict:
    """
    Build and sign a kind:1903 Twin Binding event.
    Establishes "this twin_id IS the Gaussian splat twin of this agent's IP Root."
    """
    if created_at is None:
        created_at = int(time.time())

    pubkey_hex = identity.pubkey.hex()
    ip_root_id = pubkey_hex  # agent's own pubkey is its ip_root d-tag

    tags: list = [
        ["ip_root",   ip_root_id],
        ["sim_id",    twin_id],
        ["twin_kind", "gaussian-splat-1to1"],
        ["osovm_op",  "RECEIPT", scene_receipt_id],
    ]
    if f1_score is not None:
        tags.append(["fidelity", f"{f1_score:.4f}"])

    content = json.dumps({"notes": notes})
    return _build_and_sign(pubkey_hex, created_at, KIND_TWIN_BINDING, tags, content, identity.seckey)


def build_creation_receipt_event(
    identity:         "object",
    content_sha256:   str,
    scene_receipt_id: str,
    twin_binding_id:  Optional[str],
    title:            str,
    mime_type:        str = "model/splat+ply",
    license:          Optional[str] = None,
    created_at:       Optional[int] = None,
) -> dict:
    """
    Build and sign a kind:1901 Creation Receipt for a Gaussian splat.
    """
    if created_at is None:
        created_at = int(time.time())

    pubkey_hex = identity.pubkey.hex()
    ip_root_id = pubkey_hex
    lic = license or "cc-by-4.0"

    tags: list = [
        ["ip_root",  ip_root_id],
        ["x",        content_sha256],
        ["m",        mime_type],
        ["L",        "license"],
        ["l",        lic, "license"],
        ["osovm_op", "RECEIPT", scene_receipt_id],
    ]
    if twin_binding_id:
        tags.append(["twin", twin_binding_id])

    content = json.dumps({"title": title, "description": "Sovereign Gaussian splat"})
    return _build_and_sign(pubkey_hex, created_at, KIND_CREATION_RECEIPT, tags, content, identity.seckey)


# ── Engram storage via minipae ────────────────────────────────────────────────

async def store_ip_root_engram(
    identity:      "object",
    ip_root_event: dict,
    relay_url:     str,
) -> None:
    """
    Publish the IP Root event to a Nostr relay, then store its event id
    in `mem/ip/root` as a kind:30174 engram via minipae.
    """
    # 1. Publish the kind:31900 IP Root event itself
    await minipae.publish(relay_url, ip_root_event)

    # 2. Store a reference engram — build_event handles NIP-44 encryption + d-tag
    body = {
        "ip_root_event_id": ip_root_event["id"],
        "pubkey":           ip_root_event["pubkey"],
        "kind":             ip_root_event["kind"],
        "created_at":       ip_root_event["created_at"],
    }
    engram_event = minipae.build_event(IP_ROOT_SLUG, body, identity.seckey, identity.pubkey)
    await minipae.publish(relay_url, engram_event)


async def get_ip_root_id(identity: "object", relay_url: str) -> Optional[str]:
    """Fetch ip_root_event_id from the agent's own engram store."""
    kc = minipae.conversation_key(identity.seckey, identity.pubkey)
    expected_dtag = minipae.d_tag(IP_ROOT_SLUG, kc)

    events = await minipae.query(relay_url, authors=[identity.pubkey.hex()])
    for ev in events:
        if ev.get("kind") != minipae.KIND_AGENT_ENGRAM:
            continue
        tags = {t[0]: t[1] for t in ev.get("tags", []) if len(t) >= 2}
        if tags.get("d") != expected_dtag:
            continue
        try:
            body = minipae.decode_body(ev, kc)
            return body.get("ip_root_event_id")
        except Exception:
            pass
    return None


# ── Sovereignty seal: IP Root + Twin Binding + Creation Receipt ───────────────

def seal_splat_ownership(
    identity:         "object",
    twin_id:          str,
    scene_receipt_id: str,
    splat_bytes:      bytes,
    f1_score:         Optional[float],
    title:            str,
) -> tuple:
    """
    Synchronous: build all three Nostr events for Gaussian splat ownership.

    Returns:
      (ip_root_event, twin_binding_event, creation_receipt_event)

    Publish order: ip_root → twin_binding → creation_receipt
    (timestamps staggered by 1 second each to make ordering unambiguous)
    """
    now = int(time.time())
    content_sha256 = hashlib.sha256(splat_bytes).hexdigest()

    ip_root = build_ip_root_event(
        identity     = identity,
        display_name = identity.pubkey.hex()[:12],
        created_at   = now,
    )

    twin_binding = build_twin_binding_event(
        identity         = identity,
        twin_id          = twin_id,
        scene_receipt_id = scene_receipt_id,
        f1_score         = f1_score,
        created_at       = now + 1,
    )

    creation_receipt = build_creation_receipt_event(
        identity         = identity,
        content_sha256   = content_sha256,
        scene_receipt_id = scene_receipt_id,
        twin_binding_id  = twin_binding["id"],
        title            = title,
        created_at       = now + 2,
    )

    return ip_root, twin_binding, creation_receipt
