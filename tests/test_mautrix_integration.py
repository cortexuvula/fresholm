"""Integration tests that exercise real mautrix against fresholm's compat layer.

These tests self-skip when mautrix is not installed. Install with:
    pip install -e ".[dev]"

Note: mautrix import order matters. fresholm.import_hook MUST run before any
test imports mautrix.crypto. Because pytest does not isolate sys.modules
between test files within a session, this file installs the hook at module
load time (before importorskip), and assumes no other test file in the suite
imports mautrix without the hook first. Today, this is the only file that
imports mautrix at all.
"""

import sys

import fresholm.import_hook  # noqa: F401  -- side-effect import, must run first
import fresholm.compat.olm

import pytest

mautrix = pytest.importorskip("mautrix")


def test_import_hook_makes_olm_resolve_to_fresholm():
    """sys.modules['olm'] points at fresholm.compat.olm after the hook runs."""
    import olm  # noqa: F401  -- routed through the hook
    assert sys.modules["olm"] is fresholm.compat.olm


def test_mautrix_crypto_imports_against_fresholm():
    """mautrix.crypto loads successfully against fresholm's import hook + _libolm
    stub. Verified empirically against mautrix 0.21:

    - mautrix.crypto does NOT re-export PkSigning or Account at the module
      level, so an identity check on those would be a no-op (vacuous pass).
      The check is omitted to avoid false confidence.
    - mautrix.crypto.Session exists but is mautrix's own wrapper class, not
      fresholm's Session. callable() is the strongest assertion that's true.
    """
    import mautrix.crypto  # noqa: F401

    assert callable(mautrix.crypto.Session), \
        "mautrix.crypto.Session is not callable"


# Regression test for commit 4058c6c — mautrix>=0.21 passes additional kwargs
# through to *.from_pickle(). The compat layer must accept and ignore them.

# Kwargs discovered from mautrix source (Step 1 of Task 4). Update if mautrix
# adds more in a future release.
#
# Known set from commit 4058c6c: shared, creation_time, last_encrypted,
# last_decrypted, signing_key, sender_key, room_id.
#
# Additional kwargs found in mautrix source during Step 1 discovery:
#   forwarding_chain, ratchet_safety, received_at, max_age, max_messages,
#   is_scheduled (InboundGroupSession.from_pickle)
#   use_time, message_count (OutboundGroupSession.from_pickle)
MAUTRIX_FROM_PICKLE_KWARGS = {
    "shared": True,
    "creation_time": 0,
    "last_encrypted": 0,
    "last_decrypted": 0,
    "signing_key": "fake_signing_key",
    "sender_key": "fake_sender_key",
    "room_id": "!room:example.org",
    "forwarding_chain": [],
    "ratchet_safety": None,
    "received_at": None,
    "max_age": None,
    "max_messages": None,
    "is_scheduled": False,
    "use_time": None,
    "message_count": 0,
}


def test_account_from_pickle_accepts_mautrix_kwargs():
    from fresholm.compat.olm import Account
    acct = Account()
    blob = acct.pickle("test-passphrase")
    restored = Account.from_pickle(blob, "test-passphrase", **MAUTRIX_FROM_PICKLE_KWARGS)
    assert restored.identity_keys == acct.identity_keys


def test_session_from_pickle_accepts_mautrix_kwargs():
    from fresholm.compat.olm import Account, Session
    alice, bob = Account(), Account()
    bob.generate_one_time_keys(1)
    bob_otk = next(iter(bob.one_time_keys["curve25519"].values()))
    bob.mark_keys_as_published()
    sess = alice.new_outbound_session(bob.identity_keys["curve25519"], bob_otk)
    blob = sess.pickle("test-passphrase")
    restored = Session.from_pickle(blob, "test-passphrase", **MAUTRIX_FROM_PICKLE_KWARGS)
    assert restored.id == sess.id


def test_outbound_group_session_from_pickle_accepts_mautrix_kwargs():
    from fresholm.compat.olm import OutboundGroupSession
    out = OutboundGroupSession()
    blob = out.pickle("test-passphrase")
    restored = OutboundGroupSession.from_pickle(blob, "test-passphrase", **MAUTRIX_FROM_PICKLE_KWARGS)
    assert restored.id == out.id


def test_inbound_group_session_from_pickle_accepts_mautrix_kwargs():
    from fresholm.compat.olm import OutboundGroupSession, InboundGroupSession
    out = OutboundGroupSession()
    inb = InboundGroupSession(out.session_key)
    blob = inb.pickle("test-passphrase")
    restored = InboundGroupSession.from_pickle(blob, "test-passphrase", **MAUTRIX_FROM_PICKLE_KWARGS)
    assert restored.id == inb.id


# ---------------------------------------------------------------------------
# Scenario 3: PkSigning round-trip
# ---------------------------------------------------------------------------
# Step 1 findings:
#   - mautrix.crypto.cross_signing_key: instantiates olm.PkSigning(seed) in
#     CrossSigningSeeds.to_keys() and CrossSigningPrivateKeys (lines 41-43).
#   - mautrix.crypto.signature.sign_olm: accepts an olm.PkSigning (or
#     olm.Account) and calls key.sign(canonical_json(data)) where data is a
#     dict with "signatures" and "unsigned" stripped first.
#   - Both call sites are pure-Python in fresholm's compat layer (no CFFI),
#     so they are safely exercisable in standalone tests without an async
#     event loop or network.
# ---------------------------------------------------------------------------


def test_pk_signing_signature_verifies_with_fresholm():
    """Round-trip: PkSigning.sign produces a signature fresholm's own
    ed25519_verify accepts.  This uses only fresholm's crypto — no mautrix
    code path — so it must always pass.
    """
    from fresholm.compat.olm import PkSigning, ed25519_verify

    seed = PkSigning.generate_seed()
    signer = PkSigning(seed)
    message = '{"key":"value"}'  # canonical JSON shape
    signature = signer.sign(message)
    pub = signer.public_key

    # Round-trip: signature produced by PkSigning.sign verifies via ed25519_verify
    ed25519_verify(pub, message, signature)  # raises on failure


def test_pk_signing_via_mautrix_signs_and_verifies():
    """mautrix.crypto.signature.sign_olm uses PkSigning internally (via the
    olm.PkSigning alias resolved by fresholm's import hook).  Verify that the
    signature it produces can be independently verified by fresholm's
    ed25519_verify, exercising the full interop path:

        fresholm.PkSigning → mautrix.sign_olm → fresholm.ed25519_verify

    Also exercises CrossSigningSeeds.to_keys() (mautrix.crypto.cross_signing_key)
    which instantiates olm.PkSigning(seed) from a generated 32-byte seed.
    """
    from fresholm.compat.olm import ed25519_verify
    from mautrix.crypto.cross_signing_key import CrossSigningSeeds
    from mautrix.crypto.signature import sign_olm, canonical_json

    # Generate cross-signing seeds via the mautrix helper (uses olm.PkSigning
    # under the hood, resolved to fresholm.compat.olm.PkSigning by the hook).
    seeds = CrossSigningSeeds.generate()
    keys = seeds.to_keys()
    pub = keys.public_keys.master_key

    # sign_olm is the exact call shape mautrix uses in cross_signing.py and
    # device_lists.py — it strips "signatures"/"unsigned" then calls
    # key.sign(canonical_json(data)).
    payload = {"user_id": "@alice:example.org", "usage": ["master"], "keys": {}}
    # Capture the canonical form *before* sign_olm mutates the dict.
    expected_signed_message = canonical_json(payload)
    signature = sign_olm(payload, keys.master_key)

    # Verify: the signature mautrix produced validates against fresholm's verifier.
    ed25519_verify(pub, expected_signed_message, signature)  # raises on failure
