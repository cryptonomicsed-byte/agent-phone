"""
NIP-46 remote signing for the phone process.

The phone process is network-exposed by definition, so it must never hold the
agent's long-term nsec. It holds a throwaway transport key and talks to a
NIP-46 bunker (the agent's signer — Vantage already runs a compatible one).
A compromised phone process then costs a session, not the identity.

`PhoneSigner` wraps minipae.Nip46Client so the rest of the package can call a
single `sign_event` and get back a verified, agent-signed event.
"""
from __future__ import annotations

import secrets

import minipae

from .identity import Identity


def build_unsigned(kind: int, content: str, tags: list, pubkey_hex: str) -> dict:
    """A NIP-01 event missing only id/sig — ready for a NIP-46 bunker."""
    return {
        "kind": kind,
        "pubkey": pubkey_hex,
        "created_at": int(minipae.time.time()),
        "tags": tags,
        "content": content,
    }


class PhoneSigner:
    """Remote signer: a transport key + a NIP-46 bunker holding the agent key."""

    def __init__(self, bunker_uri: str, transport_seckey: bytes | None = None, timeout: float = 75.0):
        self.bunker_uri = bunker_uri
        self.transport_seckey = transport_seckey or secrets.token_bytes(32)
        self._client = minipae.Nip46Client(bunker_uri, self.transport_seckey, timeout)
        self._agent_pubkey: str | None = None

    async def connect(self) -> str:
        await self._client.connect()
        self._agent_pubkey = await self._client.get_public_key()
        return self._agent_pubkey

    @property
    def agent_npub(self) -> str:
        if not self._agent_pubkey:
            raise RuntimeError("not connected — call connect() first")
        return minipae.npub_encode(bytes.fromhex(self._agent_pubkey))

    async def sign_event(self, kind: int, content: str, tags: list) -> dict:
        """Sign an event with the agent's key (held by the bunker)."""
        if not self._agent_pubkey:
            raise RuntimeError("not connected — call connect() first")
        unsigned = build_unsigned(kind, content, tags, self._agent_pubkey)
        return await self._client.sign_event(unsigned)

    async def close(self) -> None:
        # Nip46Client has no explicit close; sessions are short-lived by design.
        return None
