"""
agent-phone CLI — exercise the sovereign telecom stack without a UI.

Commands:
    identity              birth a fresh identity (prints nsec + npub + metadata)
    binding               emit the binding engram (npub -> optional attrs)
    heartbeat             emit a signed presence event
    offer <npub> <sdp>    gift-wrap an offer to another agent
    answer <event.json>   decrypt an incoming offer (prints parsed signal)
    voicemail <npub> ...  emit a voicemail engram referencing a Blossom blob

All commands are offline by default (they build + sign events); pass --relay
to publish. The identity is read from AGENT_PHONE_NSEC or --nsec.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

import minipae

from .identity import Identity, build_binding_engram, build_metadata_event
from .presence import build_heartbeat
from .signaling import build_offer, parse_signal, unwrap_gift_wrap
from .voicemail import build_voicemail_engram
from .reticulum import derive_reticulum_hash


def _load_identity(args) -> Identity:
    nsec = args.nsec or __import__("os").environ.get("AGENT_PHONE_NSEC", "").strip()
    if not nsec:
        print("error: no identity — pass --nsec or set AGENT_PHONE_NSEC", file=sys.stderr)
        sys.exit(2)
    return Identity.from_nsec(nsec)


def cmd_identity(args) -> None:
    ident = Identity.generate() if args.generate else _load_identity(args)
    print(json.dumps({"nsec": ident.nsec, "npub": ident.npub, "pubkey": ident.pubkey_hex}, indent=2))
    if args.meta:
        ev = build_metadata_event(ident, args.name or "agent-phone")
        print(json.dumps(ev, indent=2))


def cmd_binding(args) -> None:
    ident = _load_identity(args)
    reticulum = args.reticulum or derive_reticulum_hash(ident.seckey)
    ev = build_binding_engram(
        ident,
        nip05=args.nip05,
        suins=args.suins,
        sui_address=args.sui,
        reticulum_hash=reticulum,
    )
    print(json.dumps(ev, indent=2))


def cmd_heartbeat(args) -> None:
    ident = _load_identity(args)
    ev = build_heartbeat(ident, args.relays, note=args.note)
    print(json.dumps(ev, indent=2))


def cmd_offer(args) -> None:
    ident = _load_identity(args)
    callee_pubkey = minipae.npub_decode(args.callee)
    ev = build_offer(ident, callee_pubkey, args.sdp)
    print(json.dumps(ev, indent=2))


def cmd_decrypt(args) -> None:
    ident = _load_identity(args)
    with open(args.event) as f:
        ev = json.load(f)
    if args.parse:
        print(json.dumps(parse_signal(ev, ident).__dict__, indent=2))
    else:
        print(unwrap_gift_wrap(ev, ident))


def cmd_voicemail(args) -> None:
    ident = _load_identity(args)
    ev = build_voicemail_engram(
        ident, args.caller, args.sha256, args.blossom,
        duration_s=args.duration, transcript=args.transcript,
    )
    print(json.dumps(ev, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent-phone", description=__doc__)
    p.add_argument("--nsec", help="agent secret key (nsec1...) or env AGENT_PHONE_NSEC")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("identity")
    s.add_argument("--generate", action="store_true")
    s.add_argument("--meta", action="store_true")
    s.add_argument("--name")
    s.set_defaults(func=cmd_identity)

    s = sub.add_parser("binding")
    s.add_argument("--nip05"); s.add_argument("--suins"); s.add_argument("--sui"); s.add_argument("--reticulum")
    s.set_defaults(func=cmd_binding)

    s = sub.add_parser("heartbeat")
    s.add_argument("--relays", nargs="+", default=["wss://relay.damus.io"])
    s.add_argument("--note", default="")
    s.set_defaults(func=cmd_heartbeat)

    s = sub.add_parser("offer")
    s.add_argument("callee"); s.add_argument("sdp")
    s.set_defaults(func=cmd_offer)

    s = sub.add_parser("decrypt")
    s.add_argument("event"); s.add_argument("--parse", action="store_true")
    s.set_defaults(func=cmd_decrypt)

    s = sub.add_parser("voicemail")
    s.add_argument("caller"); s.add_argument("sha256"); s.add_argument("blossom")
    s.add_argument("--duration", type=float); s.add_argument("--transcript", default="")
    s.set_defaults(func=cmd_voicemail)

    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
