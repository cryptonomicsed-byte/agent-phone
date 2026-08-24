"""Unit tests for the Reticulum/LXMF fallback transport (Phase 7)."""
import tempfile

import pytest

import RNS

import agent_phone.reticulum as reticulum
from agent_phone import (
    Identity,
    ReticulumIdentity,
    derive_reticulum_hash,
    derive_reticulum_seed,
)


@pytest.fixture(scope="module")
def rns_instance():
    """Start an in-process RNS instance so Destination/LXMF can be exercised."""
    d = tempfile.mkdtemp(prefix="rns-test-")
    r = RNS.Reticulum(configdir=d, loglevel=RNS.LOG_CRITICAL)
    yield r


def test_derive_seed_is_deterministic_and_64_bytes():
    ident = Identity.generate()
    s1 = derive_reticulum_seed(ident.seckey)
    s2 = derive_reticulum_seed(ident.seckey)
    assert len(s1) == 64
    assert s1 == s2

    other = Identity.generate()
    assert derive_reticulum_seed(other.seckey) != s1


def test_derive_hash_format_and_stability():
    ident = Identity.generate()
    h1 = derive_reticulum_hash(ident.seckey)
    h2 = derive_reticulum_hash(ident.seckey)
    assert h1 == h2
    assert len(h1) == 32  # RNS truncated destination hash, hex
    assert all(c in "0123456789abcdef" for c in h1)


def test_reticulum_identity_matches_derive_hash():
    ident = Identity.generate()
    rid = ReticulumIdentity(ident.seckey)
    assert rid.reticulum_hash == derive_reticulum_hash(ident.seckey)
    # Deterministic across instances.
    assert ReticulumIdentity(ident.seckey).reticulum_hash == rid.reticulum_hash


def test_reticulum_destination(rns_instance):
    ident = Identity.generate()
    rid = ReticulumIdentity(ident.seckey)
    dest = rid.destination("agent-phone")
    assert dest is not None
    assert len(dest.hash) == 16  # a valid RNS destination hash


def test_fallback_requires_lxmf(rns_instance):
    """ReticulumFallback construction with LXMF installed + RNS running."""
    pytest.importorskip("LXMF", reason="LXMF not installed")
    ident = Identity.generate()
    fb = reticulum.ReticulumFallback(ident.seckey)
    assert fb.reticulum_hash == derive_reticulum_hash(ident.seckey)
