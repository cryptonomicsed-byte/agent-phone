"""
Identity — npub root, kind:0 metadata, and the binding engram.

The identity root is the npub. Everything right of the arrow in the binding
record is optional:

    npub  ->  { nip05?, suins?, sui_address?, reticulum_hash }

An agent with none of the optional attributes is still discoverable, callable
and rememberable — that is the test for whether Sui is genuinely optional.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field

import minipae

KIND_METADATA = 0
BINDING_SLUG = "mem/phone/identity"


@dataclass
class Identity:
    """A sovereign agent identity rooted at an npub."""

    seckey: bytes
    pubkey: bytes = field(init=False)

    def __post_init__(self) -> None:
        if len(self.seckey) != 32:
            raise ValueError("seckey must be 32 bytes")
        minipae._validate_seckey(int.from_bytes(self.seckey, "big"))
        self.pubkey = minipae.pubkey_from_secret(int.from_bytes(self.seckey, "big"))

    # -- encodings ---------------------------------------------------------
    @property
    def nsec(self) -> str:
        return minipae.nsec_encode(self.seckey)

    @property
    def npub(self) -> str:
        return minipae.npub_encode(self.pubkey)

    @property
    def pubkey_hex(self) -> str:
        return self.pubkey.hex()

    # -- constructors ------------------------------------------------------
    @classmethod
    def generate(cls) -> "Identity":
        """Birth a fresh identity from hardware/OS entropy."""
        return cls(secrets.token_bytes(32))

    @classmethod
    def from_nsec(cls, nsec: str) -> "Identity":
        return cls(minipae.nsec_decode(nsec))


def build_metadata_event(
    identity: Identity,
    name: str,
    about: str = "",
    picture: str = "",
    nip05: str | None = None,
) -> dict:
    """NIP-01 kind:0 metadata, signed by the agent's npub."""
    content: dict = {"name": name}
    if about:
        content["about"] = about
    if picture:
        content["picture"] = picture
    if nip05:
        content["nip05"] = nip05
    return minipae.sign_event(
        KIND_METADATA,
        json.dumps(content),
        [],
        identity.seckey,
    )


def build_binding_engram(
    identity: Identity,
    nip05: str | None = None,
    suins: str | None = None,
    sui_address: str | None = None,
    reticulum_hash: str | None = None,
) -> dict:
    """The binding record: npub -> {optional attributes}.

    Published as a kind:30174 engram under `mem/phone/identity`. The npub is
    the author and therefore the root; the body maps only optional attributes.
    """
    body: dict = {"npub": identity.npub}
    if nip05:
        body["nip05"] = nip05
    if suins:
        body["suins"] = suins
    if sui_address:
        body["sui_address"] = sui_address
    if reticulum_hash:
        body["reticulum_hash"] = reticulum_hash

    owner_pubkey = identity.pubkey  # self-owned binding
    ev = minipae.build_event(BINDING_SLUG, body, identity.seckey, owner_pubkey)
    # Attach NIP-32 labels so readers can filter without parsing content.
    ev["tags"] = ev.get("tags", []) + minipae.label_tags("phone", "binding")
    # Re-sign: adding tags after build_event invalidates id/sig. Rebuild id+sig.
    ev.pop("id", None)
    ev.pop("sig", None)
    ev["id"] = minipae.event_id(ev)
    ev["sig"] = minipae.schnorr_sign(
        bytes.fromhex(ev["id"]), int.from_bytes(identity.seckey, "big"), secrets.token_bytes(32)
    ).hex()
    return ev
