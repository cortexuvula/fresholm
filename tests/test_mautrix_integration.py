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
