# agent-phone

Sovereign, verifiable AI-agent communications stack. An agent's "phone number"
is a `.sui` identity backed by a TEE-attested brain, encrypted persistent
memory, and censorship-resistant discovery/signaling.

## Architecture

> **Repositioned 2026-08-20:** Nostr is now the identity root, not the
> signaling channel. SuiNS/Seal/Walrus become optional. See
> [NOSTR_INTEGRATION.md](NOSTR_INTEGRATION.md) for what inverts, what is
> traded (human-readable naming), and what genuinely stays on SUI
> (Nautilus attestation).

| Layer | Tech | Role |
|---|---|---|
| Compute | Nautilus (AWS Nitro Enclave) | Verifiable private compute — the agent's "brain". Every response is signed by an enclave-held ephemeral key whose attestation is checked on-chain. |
| Memory | **NIP-44 + Blossom** (Seal/Walrus optional) | Encrypted engrams plus relay-served blob storage (`kind:24242`, live in Vantage). Seal/Walrus remain an optional durability tier for objects that must outlive relay retention. |
| Identity | **Nostr npub (NIP-06)** | Identity root. Naming is NIP-05 by default, SuiNS optional. Binding record reads npub → { nip05?, suins?, sui_address?, reticulum_hash } — everything right of the arrow optional. |
| Presence / signaling | Nostr (NIP-01/05/17/44/46/65, NIP-AC) | Heartbeat presence + gift-wrapped call setup (offer/answer/ICE/hangup). NIP-46 keeps the agent key out of the phone process. NIP-05 may optionally be SuiNS-backed rather than DNS-backed. |
| Media | WebRTC | Actual voice/video, P2P (SFU for group calls). |
| Fallback transport | Reticulum + LXMF | Off-grid / resilient path — Ed25519 signing, X25519 ephemeral ECDH, LoRa/packet-radio/TCP-IP/I2P agnostic, store-and-forward via Propagation Nodes. |
| Legacy bridge (deferred) | AgentPhone/Somleng-style PSTN bridge | Optional, not started. Lets a plain phone call reach an agent. |

## Implementation status (2026-08-24)

The Nostr-native telecom stack is now **real code** — a Python package
(`agent_phone/`) built on top of minipae (BIP-340 + NIP-44 v2 + NIP-AE).
Nautilus stays the only Sui dependency and remains deferred; the brain runs
as an ordinary process and the wire format is identical either way.

**Implemented (8/8 unit tests green):**

- `identity.py` — npub root (NIP-06), kind:0 metadata, binding engram
  (`mem/phone/identity` → `npub → {nip05?, suins?, sui_address?, reticulum_hash}`)
- `signaling.py` — NIP-17 gift-wrapped call signaling (offer/answer/ICE/hangup)
  + a `CallSession` state machine
- `presence.py` — NIP-65 relay list + heartbeat presence (kind:10002)
- `voicemail.py` — voicemail engram + Blossom blob reference
- `nip46.py` — `PhoneSigner`: transport-key remote signing so the network-exposed
  phone process never holds the agent nsec
- `cli.py` — `identity`, `binding`, `heartbeat`, `offer`, `decrypt`, `voicemail`

**Still open:** Phase 1 (Nautilus — blocked on AWS Free Tier verification),
Phase 7 (Reticulum/LXMF fallback), Phase 9 (payments — flag-gated), Phase 10
(PSTN — deferred).

## Build order (10 phases)

1. **Nautilus enclave on real Nitro hardware, prove attestation** — 🔴 BLOCKED (see below)
2. ✅ NIP-44 + Blossom memory (identity + binding + voicemail engrams) — *done*
3. Wire enclave to NIP-44/Blossom memory (deferred with Phase 1)
4. ✅ npub identity binding (NIP-05 default, SuiNS optional) — *done*
5. ✅ Nostr heartbeat presence (kind:10002) — *done*
6. ✅ NIP-17 gift-wrapped signaling (offer/answer/ICE/hangup) — *done* (WebRTC media is out-of-band)
7. Reticulum/LXMF fallback transport — open
8. ✅ Voicemail store-and-forward (NIP-44 + Blossom) — *done*
9. Payments / spam resistance — ⚠️ flag-gated, not live
10. Optional PSTN bridge (deferred, not started)

## Current status (2026-08-19)

**Phase 1 is blocked**, not idle. Everything short of the actual instance boot
is done and reusable:

- Local Nautilus build/run verified end-to-end (weather-example, signed
  responses confirmed working)
- `enclave/configure_enclave.sh` executed: Secrets Manager secret, IAM role,
  security group, EC2 key pair (`~/.ssh/agent-phone-key.pem`) all provisioned
- Security group hardened (2026-08-19): SSH (22) and dev port 3000 were
  previously open to `0.0.0.0/0`; now restricted to the operator's own public
  IP at config-generation time. Only 443 (the actual public enclave endpoint)
  stays world-open.
- Unit tests in `nautilus-server` verified passing (`cargo test --lib
  --features=weather-example` — note: `--bin` reports 0 tests, the test
  modules live under `lib.rs`'s module tree, not `main.rs`)

**Blocker**: `aws ec2 run-instances --instance-type m5.xlarge` fails with
`InvalidParameterCombination: not eligible for Free Tier` on account
`058190633364`. This is an account-level restriction, not a quota problem —
no Nitro Enclaves-capable instance type is Free Tier eligible, so this blocks
regardless of instance size chosen.

### Exact unblock steps (owner action required, cannot be done via CLI)

1. Go to AWS Billing & Cost Management console → Account settings.
2. Complete identity/payment verification (the Free Tier restriction lifts
   once the account is verified as a paying/verified account, not just an
   email-confirmed sign-up).
3. Confirm here once done.

### Resume steps (once unblocked, do NOT rerun the whole config script)

Rerunning `configure_enclave.sh weather-example` will recreate a duplicate
secret/IAM role. Instead retry just the launch, reusing what's already
provisioned:

- Security group: `sg-0ad4190356c5fc9f3`
- IAM role: `role-agentphone-weather-105080`
- Key pair: `agent-phone-key` (`~/.ssh/agent-phone-key.pem`)
- `user-data.sh` already patched and present in `enclave/`

```
aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type m5.xlarge \
  --key-name agent-phone-key \
  --user-data file://user-data.sh \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":200}}]' \
  --enclave-options Enabled=true \
  --security-group-ids sg-0ad4190356c5fc9f3
```

Then follow `enclave/UsingNautilus.md` from the SSH step onward.

## Cross-pillar notes

- Reached out to Sacred Core (pane wG) 2026-08-19 to check for a real
  integration point (agent-phone `.sui` identity as an auth method). No
  forced connection — waiting on their read of the fit.

## Phase 10 interim option — agentphone.ai assessment (2026-08-22)

Phase 10 (PSTN bridge, deferred) has a working hosted stand-in available
NOW as an interim carrier while the sovereign stack matures:

- **agentphone.ai** is a closed-source SaaS whose product IS the deferred
  capability: agents get real phone numbers, SMS, and voice calls with
  per-agent system prompts/voices and webhook delivery.
- **API**: 92-op OpenAPI spec is public (`/openapi.json` at agentphone.ai;
  base `https://api.agentphone.ai`). Auth is `Authorization: Bearer
  <key>`; keys use Stripe-style `sk_live_` naming. Account usage snapshot
  from assessment: 1 number / 10, 1 call, agent "Bino Elgua's Agent".
- **Open-source split**: the platform is proprietary, but client adapters
  are MIT — `AgentPhone-AI/agentphone-mcp` (MCP server, hosted at
  `mcp.agentphone.ai/mcp`), `crewai-agentphone`, `openai-agents-agentphone`,
  `chat-sdk-adapter`. Pull the MCP server into SIM for the full
  numbers/SMS/calls tool surface.
- **Webhooks**: `https://agentphone.ai/webhooks` is the delivery-config
  surface; call/SMS events can trigger SIM workflows or any endpoint we
  point it at.
- **Key hygiene**: a live account key was assessed during this note's
  research and is considered EXPOSED (passed through chat) — rotate in
  Settings → API keys before any real use; never commit key values (house
  secret-scan applies; the repo's own hard boundary on keys extends to
  this integration).
- **Plan**: use agentphone.ai as the interim PSTN carrier behind the
  sovereign identity layer, and keep their OpenAPI spec as the contract
  reference for building phase 10 self-hosted (Somleng-style) later.

## Hard boundaries

- Never accept raw AWS access keys/secret keys via chat. Always use the
  browser-based `aws login` flow.
- Phases 8–9 (anything touching real money movement): live/production
  fund-moving execution stays off/gated. Flag, don't flip, regardless of
  standing autonomous-work authorization — requires the owner's own explicit
  message naming the specific flag to enable.
