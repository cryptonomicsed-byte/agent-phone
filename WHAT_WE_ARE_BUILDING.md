# agent-phone — Full Architecture Breakdown

## The core idea

A sovereign AI agent needs a "phone number" — a way to be **discovered**, **called**, **talked to**, and **remembered**, without depending on any centralized platform (no Twilio, no phone carrier, no app-store-gated app). Every layer is chosen so the agent owns its own identity, its own memory, and its own reachability, with cryptography substituting for institutional trust wherever possible.

Think of it as: **SuiNS is the agent's phone number, Nostr is the ringing, WebRTC is the call, Reticulum is the backup line when the internet is down, and Nautilus/Seal/Walrus are how it thinks and remembers privately.**

---

## Layer by layer

### 1. Identity — SuiNS (`.sui`)
The root of trust. A human-readable name (`myagent.sui`) resolves to a Sui address, which is bound to:
- a Nostr public key (`npub`) — for discovery/signaling
- a Reticulum destination hash — for fallback transport
- (optionally) an on-chain Nautilus enclave object ID — for verifiable compute

This is the one thing everything else hangs off of. Anyone who knows `myagent.sui` can look up how to reach the agent through every channel it supports.

### 2. Discovery & presence — Nostr
Nostr relays act as a decentralized "is this agent online" bulletin board:
- **Heartbeat events**: the agent periodically publishes a signed "I'm alive, here's how to reach me" event.
- **NIP-05-style verification**: instead of the usual `.well-known/nostr.json` on a web server, we verify identity against the SuiNS record — so the "phone book" is on-chain, not DNS.
- **NIP-AC (gift-wrapped signaling)**: call setup — offer/answer/ICE candidates/hangup — travels as encrypted, gift-wrapped Nostr events (NIP-17/NIP-44 style), so relays can't see who's calling whom or the call contents, only that *some* wrapped event passed through.

Nostr is just the ringing/signaling channel — it never carries actual voice/video.

### 3. Media — WebRTC
Once two parties have exchanged signaling via Nostr, they establish a direct P2P WebRTC connection for actual audio/video/data. Peer-to-peer first; an SFU (media relay) is a later addition for group calls or NAT situations that can't punch through.

### 4. Resilient fallback — Reticulum + LXMF
If normal internet/relays are down (off-grid, disaster, censorship, no signal), Reticulum provides a transport-agnostic mesh (works over LoRa, packet radio, WiFi, TCP/IP, I2P — anything). LXMF rides on top of it as a delay/disruption-tolerant messaging protocol with **Propagation Nodes** that store-and-forward messages until the recipient reappears. This is the "the call can't get through, but the message will eventually arrive" layer — the agent's answering machine for when everything else fails.

### 5. Private compute — Nautilus (AWS Nitro Enclave TEE)
The agent's actual "brain" — decision logic, reasoning, anything sensitive — runs inside a hardware Trusted Execution Environment. It produces a cryptographic **attestation** ("this exact unmodified code produced this output") that's verifiable on-chain via a Move contract (`enclave.move`). This is what lets a caller trust the agent's behavior without trusting the operator. *(Currently optional/deferred — see below.)*

### 6. Private memory — Seal + Walrus
- **Walrus**: decentralized blob storage on Sui — where the agent's memory, voicemail, call transcripts, etc. actually live.
- **Seal**: Sui-native encryption/access-control — encrypts that data and enforces who/what can decrypt it (e.g., only the agent's own enclave, or an authorized caller).

This is the "the agent remembers things, and only it — or whoever it explicitly permits — can read them" layer.

### 7. Payments / spam resistance — Sui micropayments
Small Sui payments gate call requests or messages, similar to how a stamp discourages spam mail. Also the natural rail for any agent-to-agent or human-to-agent paid interaction (e.g., "leave a voicemail for $0.01").

### 8. Optional — PSTN bridge (deferred)
A Somleng/AgentLine-style bridge so a real telephone can still dial into the agent. Explicitly last-priority/optional — nice-to-have for legacy reachability, not core to the sovereign-agent thesis.

---

## Build order (locked) and why

1. **Nautilus** (verifiable compute) — *currently blocked* on AWS Free Tier account verification; proven working locally, blocked on real hardware attestation only.
2. **Seal + Walrus** — private memory, standalone-provable independent of Nautilus.
3. **Wire enclave ↔ Seal/Walrus** — so the brain can read/write private memory.
4. **SuiNS identity binding** — anchor the phone number.
5. **Nostr heartbeat** — presence/discoverability.
6. **NIP-AC signaling + first WebRTC call** — the actual "phone call" milestone.
7. **Reticulum/LXMF fallback** — resilience layer.
8. **Voicemail store-and-forward** — using Walrus/Seal + LXMF propagation nodes.
9. **Payments/spam resistance**.
10. **PSTN bridge** (optional, last).

The rationale for Nautilus-first was: prove the trust root (verifiable compute) before building everything that depends on trusting the agent's behavior. But Nautilus is additive, not foundational plumbing — phases 2–10 don't actually require it. If AWS account verification stays stuck, the entire telecom stack (identity → discovery → calling → fallback → memory → payments) can be built with the brain running as an ordinary off-chain process, and Nautilus slotted in later as a trust upgrade.

---

## Current real state

- Nautilus's local (non-attested) build is proven working end-to-end (`process_data` endpoint verified via curl).
- Real hardware attestation is blocked on AWS Free Tier account verification (account-level restriction, not a quota issue) — all AWS infra (key pair, IAM role, Secrets Manager secret, security group, patched `run.sh`) is pre-provisioned and ready to launch the instant verification clears.
- Everything else (Seal/Walrus, SuiNS, Nostr, WebRTC, Reticulum/LXMF, payments, PSTN) is designed/locked but unbuilt.
