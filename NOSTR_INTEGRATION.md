# Nostr Integration — agent-phone

Repositioned per the ecosystem directive: **Nostr is the core, SUI is
optional.** This repo is where that inverts the most, because the locked
architecture currently makes SuiNS the root of trust and Nostr "just the
ringing".

Nothing here is built yet — Phase 1 is blocked on Nitro hardware — which makes
this the cheapest possible moment to change the root.

## What inverts

| Layer | Was | Becomes | Why |
|---|---|---|---|
| Identity root | SuiNS `.sui` | **npub** (NIP-06) | The npub is already the ecosystem-wide agent identifier. Sui address becomes an attribute of the agent, not its name. |
| Naming | SuiNS | **NIP-05**, SuiNS optional | See the trade below — this is the one real loss. |
| Memory | Seal + Walrus | **NIP-44 + Blossom** | Blossom (`kind:24242`) is live in Vantage today, served by the relay's own HTTP surface. |
| Presence | Nostr | unchanged | Already Nostr. |
| Signaling | NIP-17/44 gift wrap | unchanged | Already Nostr. |
| Media | WebRTC | unchanged | Never touched either stack. |
| Fallback | Reticulum/LXMF | unchanged | Independent of both. |
| Attestation | Nautilus on-chain | **stays SUI** | No Nostr equivalent — see below. |

## Naming: NIP-05 default, SuiNS optional — decided

**npub is the root. NIP-05 is the default name. SuiNS is an optional stronger
binding for agents that want it.**

The trade is real and worth stating plainly rather than glossing: SuiNS
resolves through an on-chain record, NIP-05 through DNS. Taking NIP-05 as the
default reintroduces a registrar and a DNS operator into a stack chosen to
avoid institutional trust.

What makes it the right default anyway is the failure mode. A name here is a
convenience layer over an address that already works: **an unresolvable NIP-05
leaves the npub perfectly reachable, because the npub *is* the address.** The
DNS dependency can go down without any agent becoming uncallable. The reverse
arrangement — SuiNS as root — makes chain availability a precondition for
reachability, which is a strictly worse thing to depend on for a component
whose whole purpose is being reachable.

So the binding record reads:

```
npub  →  { nip05?, suins?, sui_address?, reticulum_hash }
```

Everything to the right of the arrow is optional. An agent with none of it is
still discoverable, callable and rememberable — which is the test for whether
SUI is genuinely optional rather than nominally so.

Agents that want a stronger name register SuiNS *pointing at the npub* and
publish it in the binding record. NIP-05 and SuiNS then coexist: two names for
one address, neither of them the root.

## What genuinely stays on SUI

**Nautilus enclave attestation.** An enclave quote verified on-chain is a
different guarantee from one asserted in a signed event. A Nostr event can
*carry* an attestation document, and a Crucible claim can make "this response
came from an attested enclave" falsifiable — but neither verifies the quote
against a registry that an adversary cannot also write to.

If the TEE guarantee matters, that dependency is real. If it does not, Phase 1
unblocks immediately, because everything blocking it is Nitro-specific.

## Identity flow, restated

```
Birth
  → BIPON39 seed
  → NIP-06 secp256k1 at m/44'/1237'/0'/0/0     ← the identity
  → publish kind:0 metadata
  → write mem/phone/identity engram (binding record)
  → optional: register SuiNS name pointing at the npub
  → optional: Sui address for settlement only
```

The optional lines can be skipped entirely and the agent is still fully
reachable, callable and rememberable. That is the test for whether SUI is
actually optional rather than nominally optional.

## Events this repo will emit

| Event | Fires when | Kind | Labels (NIP-32) |
|---|---|---|---|
| Birth | agent provisioned | `0` + engram | `agent/birth` |
| Heartbeat | periodic presence | `10002` relay list + presence | `phone/presence` |
| Call setup | offer/answer/ICE/hangup | NIP-17 gift wrap | — (wrapped) |
| Voicemail | message stored | engram + Blossom blob ref | `phone/voicemail` |
| Binding | identity record changes | engram `mem/phone/identity` | `agent/binding` |

Call setup stays gift-wrapped: a relay should learn that *some* wrapped event
passed, not who called whom.

## Keys

Use **NIP-46** for anything the phone process runs. The enclave or bunker holds
the agent key; the phone process holds a transport key. A compromised phone
process then costs a session, not the identity — which matters more here than
almost anywhere else in the ecosystem, since this component is network-exposed
by definition.

`minipae.Nip46Client` is the client; Vantage already runs a compatible signer.

## Namespace

`mem/phone/` — register in `minipae/NAMESPACES.md` before the first write.

## Status

- [x] Namespace registered (`mem/phone/*` already listed in `minipae/NAMESPACES.md`, status: planned)
- [ ] Identity flow implemented (npub root)
- [ ] Binding record engram
- [ ] Heartbeat presence
- [ ] NIP-46 wired for the phone process
- [ ] Voicemail via Blossom
- [ ] Decide: is the Nautilus TEE guarantee required for v1?
