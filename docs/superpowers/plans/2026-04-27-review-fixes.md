# Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the three "solid" review findings — add MIT LICENSE, add a real mautrix integration test that catches API contract drift, and produce a research note on vodozemac's pickle KDF (no code change to passphrase_to_key in this plan).

**Architecture:** Three independent units, three independent commits on a single branch. License is metadata. Mautrix integration test gets a new `[dev]` extra in `pyproject.toml`, a new test file, a CI tweak, and a README touch. KDF investigation produces a markdown note with a verdict line.

**Tech Stack:** Python 3.10+, maturin, PyO3, pytest, pytest-asyncio, mautrix-python, vodozemac (Rust).

**Source spec:** `docs/superpowers/specs/2026-04-27-review-fixes-design.md`

---

## File Structure

| Path | Action | Purpose |
|------|--------|---------|
| `LICENSE` | create | SPDX MIT text |
| `pyproject.toml` | modify | Add `license`, `license-files`, `[project.optional-dependencies] dev` |
| `tests/test_mautrix_integration.py` | create | Real mautrix integration tests (self-skipping) |
| `.github/workflows/ci.yml` | modify | Install `[dev]` on Ubuntu + 3.12 entry; run integration tests there |
| `README.md` | modify | Two-line update to Development section |
| `docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md` | create | Research note + verdict on `passphrase_to_key` |

---

## Task 1: Add LICENSE file and license metadata

**Files:**
- Create: `LICENSE`
- Modify: `pyproject.toml`

- [ ] **Step 1: Create the LICENSE file**

Create `LICENSE` with the canonical SPDX MIT text:

```
MIT License

Copyright (c) 2026 Andre Hugo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Add PEP 639 license metadata to pyproject.toml**

Edit `pyproject.toml`. Current `[project]` section:

```toml
[project]
name = "fresholm"
version = "0.2.4"
requires-python = ">=3.10"
dependencies = ["cryptography>=41.0"]
```

Replace with:

```toml
[project]
name = "fresholm"
version = "0.2.4"
requires-python = ">=3.10"
license = "MIT"
license-files = ["LICENSE"]
dependencies = ["cryptography>=41.0"]
```

- [ ] **Step 3: Build and verify metadata**

Run:

```bash
pip install build
python -m build --sdist
tar -tzf dist/fresholm-0.2.4.tar.gz | grep -i license
tar -xzOf dist/fresholm-0.2.4.tar.gz fresholm-0.2.4/PKG-INFO | grep -iE "^(License|License-Expression|License-File)"
```

Expected:
- The `tar -tzf` line lists `fresholm-0.2.4/LICENSE`.
- `PKG-INFO` shows either `License-Expression: MIT` (PEP 639 form succeeded) or `License: MIT` (fallback). Also shows `License-File: LICENSE`.

If the build fails with an error about the `license` field — likely an old maturin — fall back to the table form: replace the two lines added in Step 2 with:

```toml
license = {text = "MIT"}
license-files = ["LICENSE"]
```

Re-run Step 3.

- [ ] **Step 4: Build a wheel and confirm LICENSE is bundled**

Run:

```bash
python -m build --wheel
unzip -l dist/fresholm-0.2.4-*.whl | grep -i license
```

Expected: at least one line listing `fresholm-0.2.4.dist-info/LICENSE` (or similar `dist-info/LICENSE.*` path). If the LICENSE is not bundled, the maturin version may need explicit configuration — but `license-files` should handle this automatically. If missing, stop and investigate before committing.

- [ ] **Step 5: Commit**

```bash
git add LICENSE pyproject.toml
git commit -m "$(cat <<'EOF'
chore: add MIT LICENSE file and pyproject license metadata

PEP 639 license-expression form. Falls back to table form if the
pinned maturin version doesn't accept SPDX strings.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add `[dev]` extra and install mautrix locally

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add the optional-dependencies table to pyproject.toml**

Append to `pyproject.toml` (anywhere after `[project]`):

```toml
[project.optional-dependencies]
dev = [
    "pytest>=8",
    "pytest-asyncio>=0.23",
    "mautrix>=0.21",
]
```

Note: not using `mautrix[e2be]` because `e2be` pulls in `python-olm`, which has known build problems on modern macOS / CMake 3.28+. The integration test relies on fresholm's import hook, not on python-olm being co-installed.

- [ ] **Step 2: Install in the active venv and confirm mautrix imports**

Run from the repo root, in the active dev venv:

```bash
pip install -e ".[dev]"
python -c "import mautrix; import mautrix.crypto; print(mautrix.__version__)"
```

Expected: prints a version `>=0.21` (e.g., `0.21.x`). If `import mautrix.crypto` fails with `ModuleNotFoundError: No module named 'olm'`, that means mautrix.crypto hard-imports `olm` at module load time — record this finding and proceed; subsequent tests will use the import hook before importing mautrix.crypto, which fixes it.

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "$(cat <<'EOF'
chore: add [dev] optional dependencies for integration testing

Includes mautrix>=0.21 for the upcoming mautrix integration tests.
Install with: pip install -e ".[dev]"

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Scenario 1 — Import-hook end-to-end test

**Files:**
- Create: `tests/test_mautrix_integration.py`

- [ ] **Step 1: Create the test file with the import-hook scenario**

Create `tests/test_mautrix_integration.py`:

```python
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
    """mautrix.crypto loads successfully and any olm symbols it re-exposes
    point back at fresholm.compat.olm."""
    import mautrix.crypto  # noqa: F401

    # If mautrix.crypto re-exports olm-namespace symbols, identity should hold.
    # Not all versions do; gate the assertion on attribute presence rather
    # than asserting unconditionally.
    for symbol in ("PkSigning", "Account", "Session"):
        if hasattr(mautrix.crypto, symbol):
            assert getattr(mautrix.crypto, symbol) is getattr(
                fresholm.compat.olm, symbol
            ), f"mautrix.crypto.{symbol} is not fresholm.compat.olm.{symbol}"
```

- [ ] **Step 2: Run and verify pass**

Run:

```bash
pytest tests/test_mautrix_integration.py -v
```

Expected: 2 passed. If `test_mautrix_crypto_imports_against_fresholm` fails on the identity check, mautrix has rebound the symbol after import — record which symbol failed and either remove it from the loop or replace the identity check with a `callable()` check for that one symbol.

- [ ] **Step 3: Confirm self-skip works**

In a clean shell with no `[dev]` extra installed (or simulated by uninstalling mautrix), confirm:

```bash
pip uninstall -y mautrix
pytest tests/test_mautrix_integration.py -v
```

Expected: tests show `s` (skipped) with reason `could not import 'mautrix'`. Then reinstall:

```bash
pip install -e ".[dev]"
pytest tests/test_mautrix_integration.py -v
```

Expected: tests pass again.

- [ ] **Step 4: Commit**

```bash
git add tests/test_mautrix_integration.py
git commit -m "$(cat <<'EOF'
test: add mautrix integration test scaffolding (scenario 1)

Confirms fresholm.import_hook redirects sys.modules['olm'] to
fresholm.compat.olm before mautrix.crypto loads. Self-skips when
mautrix is not installed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Scenario 2 — `from_pickle` kwargs regression test

**Files:**
- Modify: `tests/test_mautrix_integration.py`

- [ ] **Step 1: Discover the exact kwargs mautrix passes to `from_pickle`**

Run:

```bash
grep -rn "from_pickle" "$(python -c 'import mautrix, os; print(os.path.dirname(mautrix.__file__))')"
```

Expected: lines showing `from_pickle(...)` calls in mautrix's crypto store. Read each call site and record the keyword argument names. The commit message of `4058c6c` lists the known set: `shared`, `creation_time`, `last_encrypted`, `last_decrypted`, `signing_key`, `sender_key`, `room_id`. The discovered set should be a superset or equal to this — if smaller, the test still uses the known list (defensive coverage); if larger, add the new ones to the test.

- [ ] **Step 2: Add the kwargs test to the integration file**

Append to `tests/test_mautrix_integration.py`:

```python
# Regression test for commit 4058c6c — mautrix>=0.21 passes additional kwargs
# through to *.from_pickle(). The compat layer must accept and ignore them.

# Kwargs discovered from mautrix source (Step 1 of Task 4). Update if mautrix
# adds more in a future release.
MAUTRIX_FROM_PICKLE_KWARGS = {
    "shared": True,
    "creation_time": 0,
    "last_encrypted": 0,
    "last_decrypted": 0,
    "signing_key": "fake_signing_key",
    "sender_key": "fake_sender_key",
    "room_id": "!room:example.org",
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
```

- [ ] **Step 3: Run and verify pass**

Run:

```bash
pytest tests/test_mautrix_integration.py -v
```

Expected: 6 passed (2 from Task 3 + 4 new). If any kwargs-test fails with `TypeError: from_pickle() got an unexpected keyword argument`, the corresponding compat method is missing `**kwargs` — fix the compat method (regression in `fresholm/compat/olm.py`).

- [ ] **Step 4: Verify the regression test would catch the original bug**

This is the TDD discipline check — confirm the new tests actually catch the bug they claim to catch.

```bash
# Save current state of the compat file
cp fresholm/compat/olm.py /tmp/olm-current.py

# Replace with the pre-fix version (parent of commit 4058c6c)
git show 4058c6c^:fresholm/compat/olm.py > fresholm/compat/olm.py

# Run the kwargs tests — expect FAIL (TypeError on unexpected kwarg)
pytest tests/test_mautrix_integration.py -v -k "from_pickle_accepts_mautrix_kwargs"

# Restore the fixed file
cp /tmp/olm-current.py fresholm/compat/olm.py
rm /tmp/olm-current.py

# Re-run — expect PASS
pytest tests/test_mautrix_integration.py -v -k "from_pickle_accepts_mautrix_kwargs"

# Confirm working tree is clean (no accidental modifications)
git status
```

Expected sequence:
1. After replacing with pre-fix version: 4 failed (TypeError on `shared`/`creation_time`/etc.).
2. After restoring: 4 passed.
3. `git status` shows clean working tree (no modifications).

If `git status` shows `fresholm/compat/olm.py` as modified, the restore didn't complete — re-run `cp /tmp/olm-current.py fresholm/compat/olm.py` or `git checkout HEAD -- fresholm/compat/olm.py`.

- [ ] **Step 5: Commit**

```bash
git add tests/test_mautrix_integration.py
git commit -m "$(cat <<'EOF'
test: add from_pickle kwargs regression tests (scenario 2)

Regression test for commit 4058c6c. mautrix>=0.21 passes
shared/creation_time/last_encrypted/last_decrypted/signing_key/
sender_key/room_id through to *.from_pickle(). All four compat
classes must accept and ignore them.

Verified the test catches the regression by temporarily reverting
the compat file to its pre-4058c6c state.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Scenario 3 — `PkSigning` round-trip via mautrix

**Files:**
- Modify: `tests/test_mautrix_integration.py`

- [ ] **Step 1: Discover where mautrix uses PkSigning**

Run:

```bash
MX="$(python -c 'import mautrix, os; print(os.path.dirname(mautrix.__file__))')"
grep -rn "PkSigning" "$MX"
grep -rn "cross_sign\|sign_canonical\|canonicaljson" "$MX/crypto" 2>/dev/null | head -30
```

Expected: locate the module where mautrix instantiates `PkSigning(seed)` and calls `.sign(...)`. Likely candidates per the README: `mautrix.crypto.cross_signing_key`, `mautrix.crypto.signature`, or a module in `mautrix.crypto` that handles cross-signing keys. Record:

- The module path (e.g., `mautrix.crypto.cross_signing_key`).
- The exact method name mautrix calls (e.g., `sign_json`, `sign`, etc.).
- The input shape (string vs bytes; canonical JSON vs raw).

- [ ] **Step 2: Add the PkSigning round-trip test**

Append to `tests/test_mautrix_integration.py`:

```python
# Scenario 3: PkSigning round-trip — mautrix's signing path produces a
# signature that fresholm's ed25519_verify accepts.
#
# This test exercises the actual call shape mautrix uses (Step 1 of Task 5).
# If mautrix has no public PkSigning helper that's safe to call without a
# full client context, fall back to instantiating fresholm's PkSigning
# directly and verifying with mautrix's signature-verification helper —
# either direction is a real interop check.


def test_pk_signing_signature_verifies_with_fresholm():
    from fresholm.compat.olm import PkSigning, ed25519_verify

    seed = PkSigning.generate_seed()
    signer = PkSigning(seed)
    message = '{"key":"value"}'  # canonical JSON shape
    signature = signer.sign(message)
    pub = signer.public_key

    # Round-trip: signature produced by PkSigning.sign verifies via ed25519_verify
    ed25519_verify(pub, message, signature)  # raises on failure


def test_pk_signing_via_mautrix_signs_and_verifies():
    """If mautrix exposes a helper that uses PkSigning internally, exercise
    it end-to-end. If no such helper is reachable without a full client
    context, this test self-skips with a recorded reason."""
    # Implementation depends on Step 1 discovery. Pseudocode shape:
    #
    #   from mautrix.crypto.<module> import <helper>
    #   sig = <helper>(seed=..., payload=...)
    #   from fresholm.compat.olm import ed25519_verify
    #   ed25519_verify(pub, payload, sig)
    #
    # Replace the body below with the real call shape from Step 1.
    pytest.skip(
        "Replace this skip with the actual mautrix signing helper from "
        "Step 1 discovery. If mautrix has no public helper reachable "
        "outside a full client, leave the skip in place with this reason."
    )
```

- [ ] **Step 3: Replace the skipped test body with discovered helper**

Using the discovery from Step 1, replace the body of `test_pk_signing_via_mautrix_signs_and_verifies` with the actual mautrix call. If no public helper is reachable, leave the skip with its descriptive reason — the first test (`test_pk_signing_signature_verifies_with_fresholm`) still validates the compat layer's signing/verification round-trip.

- [ ] **Step 4: Run and verify**

Run:

```bash
pytest tests/test_mautrix_integration.py -v -k "pk_signing"
```

Expected: at least the round-trip test passes. The mautrix-helper test either passes or self-skips with a recorded reason.

- [ ] **Step 5: Commit**

```bash
git add tests/test_mautrix_integration.py
git commit -m "$(cat <<'EOF'
test: add PkSigning round-trip integration tests (scenario 3)

Verifies fresholm.compat.olm.PkSigning produces signatures that
fresholm's own ed25519_verify accepts, and (where mautrix exposes
a reachable helper) that mautrix's signing path interoperates.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Scenario 4 — `OlmMachine` smoke construction

**Files:**
- Modify: `tests/test_mautrix_integration.py`

- [ ] **Step 1: Discover OlmMachine constructor signature**

Run:

```bash
MX="$(python -c 'import mautrix, os; print(os.path.dirname(mautrix.__file__))')"
grep -rn "class OlmMachine" "$MX/crypto"
```

Read the constructor `__init__` to record:

- Required positional/keyword arguments (likely `client`, `crypto_store`, `state_store` or similar).
- Types of each argument — does mautrix accept duck-typed objects, or strict subclasses of mautrix-internal protocols?

- [ ] **Step 2: Add the smoke test**

Append to `tests/test_mautrix_integration.py`. The exact constructor call below is a *template* — adjust positional/keyword arguments and stub interfaces to match what Step 1 discovered.

```python
import asyncio


@pytest.mark.asyncio
async def test_olm_machine_constructs_with_fresholm_memory_store():
    """mautrix.crypto.OlmMachine instantiates against fresholm's
    MemoryCryptoStore without raising. Does not run a full Matrix sync."""
    from mautrix.crypto import OlmMachine
    from fresholm.crypto_store import MemoryCryptoStore

    crypto_store = MemoryCryptoStore()

    # Minimal stubs for OlmMachine collaborators discovered in Step 1.
    # If mautrix requires a real Client, instantiate one with a stub HTTP
    # backend; if it accepts duck-typed objects, use SimpleNamespace.
    from types import SimpleNamespace
    fake_client = SimpleNamespace(mxid="@bot:example.org")
    fake_state_store = SimpleNamespace()

    # Adjust kwargs to match Step 1 discovery.
    machine = OlmMachine(
        client=fake_client,
        crypto_store=crypto_store,
        state_store=fake_state_store,
    )

    # Smoke check — instantiation completed.
    assert machine is not None
```

If `OlmMachine.__init__` requires async setup (e.g., `await machine.load()`), call it in the test body — `asyncio_mode = "auto"` in `pyproject.toml` already converts async test functions automatically.

If the constructor signature does not match the kwargs above, update the test to match Step 1 findings. Do not invent stubs that don't satisfy mautrix's actual contract — if mautrix requires a richer client object, build the minimum that gets past `__init__` and document why in a comment.

- [ ] **Step 3: Run and verify**

Run:

```bash
pytest tests/test_mautrix_integration.py -v -k "olm_machine"
```

Expected: test passes, or fails with a clear error about a missing collaborator. If it fails, refine the stub set per Step 1 and re-run. If `OlmMachine` cannot be instantiated outside a full Matrix client context (e.g., requires network on `__init__`), replace the test body with a `pytest.skip("OlmMachine requires full client context — not reachable in unit tests")` plus a comment explaining what was tried.

- [ ] **Step 4: Commit**

```bash
git add tests/test_mautrix_integration.py
git commit -m "$(cat <<'EOF'
test: add OlmMachine smoke construction test (scenario 4)

Verifies mautrix.crypto.OlmMachine instantiates against fresholm's
MemoryCryptoStore. Catches CryptoStore protocol drift between
fresholm and mautrix.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: CI — install `[dev]` extra on Ubuntu + Python 3.12

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Edit the test job to conditionally install `[dev]`**

Current `test` job (lines 15–34):

```yaml
  test:
    needs: lint
    strategy:
      matrix:
        os: [ubuntu-latest, macos-14]
        python: ["3.10", "3.12", "3.13"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
      - name: Build and test
        run: |
          python -m venv .venv
          source .venv/bin/activate
          pip install maturin pytest pytest-asyncio
          maturin develop --release
          pytest tests/ -v
```

Replace with:

```yaml
  test:
    needs: lint
    strategy:
      matrix:
        os: [ubuntu-latest, macos-14]
        python: ["3.10", "3.12", "3.13"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
      - name: Build
        run: |
          python -m venv .venv
          source .venv/bin/activate
          pip install maturin pytest pytest-asyncio
          maturin develop --release
      - name: Install [dev] extra (mautrix integration)
        if: matrix.os == 'ubuntu-latest' && matrix.python == '3.12'
        run: |
          source .venv/bin/activate
          pip install -e ".[dev]"
      - name: Test
        run: |
          source .venv/bin/activate
          pytest tests/ -v
```

The `[dev]` install only runs on the canonical Ubuntu + 3.12 entry. Other matrix entries skip the integration tests via `pytest.importorskip("mautrix")` already in the test file.

- [ ] **Step 2: Verify YAML parses locally**

Run:

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
```

Expected: no output (success). If a `yaml` error prints, fix indentation.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "$(cat <<'EOF'
ci: install [dev] extra on Ubuntu + Python 3.12 for mautrix integration tests

Other matrix entries continue to skip the integration tests via
pytest.importorskip in tests/test_mautrix_integration.py.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: README — update Development section

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the Development section install line**

Current Development section (around lines 166–176):

```
## Development

```bash
git clone https://github.com/your-org/fresholm
cd fresholm
python -m venv .venv && source .venv/bin/activate
pip install maturin pytest pytest-asyncio
maturin develop
pytest
```
```

Replace with:

```
## Development

```bash
git clone https://github.com/your-org/fresholm
cd fresholm
python -m venv .venv && source .venv/bin/activate
pip install maturin
maturin develop
pip install -e ".[dev]"
pytest
```

The `[dev]` extra includes `pytest`, `pytest-asyncio`, and `mautrix` (for integration tests in `tests/test_mautrix_integration.py`). Without `[dev]`, the integration tests self-skip via `pytest.importorskip`.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs: update Development section to use [dev] extra

Replaces the manual pytest/pytest-asyncio install with pip install -e
".[dev]", which also pulls mautrix for integration tests.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Vodozemac KDF investigation note

**Files:**
- Create: `docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md`

This task produces a research note. No code changes. The verdict line in the note determines what a future PR does about `crates/vodozemac-python/src/account.rs::passphrase_to_key`.

- [ ] **Step 1: Locate vodozemac source**

Run:

```bash
find ~/.cargo/registry -type d -name "vodozemac-0.9*" 2>/dev/null | head -5
```

Expected: a path like `~/.cargo/registry/src/index.crates.io-*/vodozemac-0.9.x`. If empty, run `cargo build --manifest-path crates/vodozemac-python/Cargo.toml` first to populate the registry, then retry.

- [ ] **Step 2: Find the pickle/encrypt code paths**

Set `VZ` to the path from Step 1. Run:

```bash
VZ="<path from Step 1>"
grep -rn "fn encrypt\|fn pickle\|AccountPickle\|SessionPickle" "$VZ/src" | head -50
grep -rn "pbkdf2\|hkdf\|argon\|scrypt\|kdf" -i "$VZ/src" | head -30
```

Read the relevant files. Specifically locate:

- The function that turns the 32-byte `passphrase_to_key` output into an actual cipher key.
- The cipher mode (AES-CBC + HMAC, AES-GCM, ChaCha20-Poly1305, etc.).
- Whether the encrypted output prepends a salt, version byte, or nonce that would survive a future KDF change.

- [ ] **Step 3: Write the investigation note**

Create `docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md`:

```markdown
# Vodozemac Pickle KDF Investigation

**Date:** 2026-04-27
**Source:** vodozemac 0.9 (path: `<from Step 1>`)
**Trigger:** Review finding that `crates/vodozemac-python/src/account.rs::passphrase_to_key`
truncates/pads to 32 bytes with no KDF. Question: is this a real weakness or a moot
wrapper before vodozemac's own KDF?

## What `passphrase_to_key` produces

A 32-byte buffer: the passphrase bytes copied in (truncated to 32 if longer) with the
remainder zero-padded. Used in 4 sites:

- `crates/vodozemac-python/src/account.rs:113` — `Account.to_encrypted_string`
- `crates/vodozemac-python/src/account.rs:120` — `Account.from_encrypted_string`
- `crates/vodozemac-python/src/session.rs:89,96` — `Session.{to,from}_encrypted_string`
- `crates/vodozemac-python/src/group_session.rs:45,52` — outbound group session
- `crates/vodozemac-python/src/inbound_group_session.rs:72,79` — inbound group session

## What vodozemac does with the 32 bytes

[Fill from Step 2 reading. Required answers:]

1. **Direct cipher key, or KDF-then-key?** [direct / HKDF / PBKDF2 / Argon2 / other]
2. **Cipher mode:** [AES-256-CBC + HMAC-SHA-256 / AES-GCM / ChaCha20-Poly1305 / other]
3. **Is there a salt in the output?** [yes / no]
4. **Is there a version byte / format header?** [yes / no — and what value]
5. **Does the format support backward-compatible KDF migration?** [yes / no — explain]

## Verdict

[Pick exactly one:]

- **(a) Real weakness.** vodozemac uses the 32 bytes directly as the cipher key with no
  internal KDF. A 1-character passphrase becomes a key with 31 known-zero bytes,
  drastically reducing brute-force cost. Replace `passphrase_to_key` with PBKDF2-HMAC-SHA-256
  (200k+ iterations) or Argon2id. Migration: add a version byte to distinguish
  pre/post-fix blobs; document as a 0.3.0 breaking change OR keep dual-decode for one
  release window.

- **(b) Moot wrapper.** vodozemac applies [HKDF/PBKDF2/Argon2] internally before using
  the 32 bytes as a cipher key. The current `passphrase_to_key` is harmless. Action:
  add a docstring to `passphrase_to_key` explaining the design, do not change behavior.

- **(c) Mixed.** [Spell out exactly where the gap is and what to do.]

## Recommended next steps

[Concrete actions for the future PR. If verdict (a): list the migration steps. If (b):
list the docstring change. If (c): both.]
```

Replace each `[Fill from Step 2 reading]` and `[Pick exactly one]` placeholder with the actual finding. Do not commit the note with placeholders intact.

- [ ] **Step 4: Self-check the note has no placeholders**

Run:

```bash
grep -nE "\[Fill|\[Pick|\[direct|\[yes|\[no|\[Spell|\[Concrete" docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md
```

Expected: no output. If any line prints, return to Step 3 and complete the missing field.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md
git commit -m "$(cat <<'EOF'
docs: investigate vodozemac pickle KDF behavior

Research note that determines whether passphrase_to_key in the Rust
crate is a real weakness or a moot wrapper. Verdict line drives the
follow-up PR's scope (real fix vs docstring-only).

No code change in this commit.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Final verification

After all 9 tasks land, run the full suite once:

```bash
pip install -e ".[dev]"
maturin develop
pytest tests/ -v
```

Expected: all tests pass on the local dev install. Integration tests run (not skipped) since `[dev]` is installed.

Also confirm the git log shows the expected linear history:

```bash
git log --oneline -10
```

Expected (in reverse-chronological order, most recent first):
- `docs: investigate vodozemac pickle KDF behavior`
- `docs: update Development section to use [dev] extra`
- `ci: install [dev] extra on Ubuntu + Python 3.12 for mautrix integration tests`
- `test: add OlmMachine smoke construction test (scenario 4)`
- `test: add PkSigning round-trip integration tests (scenario 3)`
- `test: add from_pickle kwargs regression tests (scenario 2)`
- `test: add mautrix integration test scaffolding (scenario 1)`
- `chore: add [dev] optional dependencies for integration testing`
- `chore: add MIT LICENSE file and pyproject license metadata`
- `docs: spec for review-fix work …`

If any commit is missing or out of order, do not push — investigate first.
