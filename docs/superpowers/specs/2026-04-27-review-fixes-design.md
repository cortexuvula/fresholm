# Review Fixes — Design Spec

**Date:** 2026-04-27
**Status:** Approved (pending user review of this written spec)
**Source:** Acts on the "solid" findings from `fresholm-review.md` (Week 18 review).

## Goals

Address three review findings:

1. **License gap** — no `LICENSE` file, no `license` field in `pyproject.toml`, despite README declaring MIT.
2. **Mautrix integration test** — `tests/test_mautrix_compat.py` never imports actual `mautrix`, so API contract drift between fresholm and mautrix is invisible to CI. The recent `from_pickle(**kwargs)` fix (commit `4058c6c`) is the canonical example.
3. **`passphrase_to_key` weakness** — *deferred*. Investigate vodozemac internals first; capture findings as a research note, no code change in this scope.

## Non-Goals

- Any change to `crates/vodozemac-python/src/account.rs::passphrase_to_key` or its 4 callers in this PR. A future PR will act on the investigation note.
- Any wire-format migration (passphrase change would be a 0.3.0-class breaking change; not landing here).
- Other review items (type hints, persistent crypto stores, docs site, benchmarks, etc.) — out of scope.

## Scope & Sequencing

Three independent commits on a single branch, each capable of merging on its own:

1. **License** — pure metadata; zero risk.
2. **Mautrix integration test** — additive new file + new dev extra; low risk.
3. **Vodozemac KDF investigation note** — documentation-only; zero code risk.

The passphrase fix is *not* on this branch. It blocks on the investigation note's verdict.

## Section 1 — License

### Files

- New `LICENSE` at repo root containing the canonical SPDX-form MIT license text with the copyright line:
  ```
  Copyright (c) 2026 Andre Hugo
  ```
  No deviations from the canonical text.

- `pyproject.toml` — add PEP 639 license fields under `[project]`:
  ```toml
  license = "MIT"
  license-files = ["LICENSE"]
  ```
  PEP 639 form (not the deprecated `license = {text = "MIT"}` table form). Modern maturin versions support the SPDX expression form; if the project's pinned maturin (`>=1.5,<2`) ends up choking on the string form during implementation, fall back to `license = {text = "MIT"}` and `license-files = ["LICENSE"]`. Verify by running the build and inspecting metadata, don't assume.

### Verification

`python -m build --sdist` and inspect the resulting sdist's `PKG-INFO` for:

- `License-Expression: MIT` (or `License: MIT` if the fallback table form was used)
- `License-File: LICENSE`

Also confirm the wheel bundles the LICENSE file: build a release wheel and run `unzip -l target/wheels/*.whl | grep -i license`. The `*.dist-info/` directory should contain `LICENSE`.

## Section 2 — Mautrix integration test

### File structure

- Keep existing `tests/test_mautrix_compat.py` unchanged. It tests our compat-layer shape against a hand-written model of mautrix's expectations and remains useful.
- Add new `tests/test_mautrix_integration.py`. Separate file because it has different load semantics — actually imports `mautrix`, may self-skip when mautrix isn't installed, may be slower than pure-compat tests.

### Dev dependency machinery

`pyproject.toml` currently has no `[project.optional-dependencies]` table. Add:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=8",
    "pytest-asyncio>=0.23",
    "mautrix[e2be]>=0.20",
]
```

The `e2be` extra is the one that pulls in `python-olm` upstream — installing it with our import hook in place is itself a useful integration smoke check.

The `>=0.20` floor is a placeholder; firm it up during implementation by checking the lowest mautrix version that exposes the API surface our scenarios touch.

### Skip behavior

Top of `tests/test_mautrix_integration.py`:

```python
import pytest
mautrix = pytest.importorskip("mautrix")
```

Self-skipping. CI matrix entries that don't install `[dev]` simply skip the file with no extra pytest filter required.

### CI

Modify the test job in `.github/workflows/ci.yml` (or the equivalent test workflow):

- Replace any direct `pip install pytest pytest-asyncio` step with `pip install -e ".[dev]"` *after* the `maturin develop` step.
- Apply this to the existing Linux + Python 3.12 matrix entry (or whichever single entry is currently the canonical "full test" entry). Other matrix entries (macOS, other Python versions) skip the integration tests via `importorskip` — keeps total CI time bounded since mautrix's deps are pure-Python and unlikely to break cross-platform.

### Test scenarios

Each scenario must fail today if its corresponding compat regression were re-introduced.

1. **Import-hook end-to-end**
   - `import fresholm.import_hook` then `import mautrix.crypto`.
   - Assert `mautrix.crypto.PkSigning is fresholm.compat.olm.PkSigning` (identity check, confirms the hook installed before mautrix loaded).
   - Catches: hook not running, hook running too late, missing/renamed compat symbols.

2. **`from_pickle` kwargs contract** (regression test for commit `4058c6c`)
   - Construct `Account`, `Session`, `OutboundGroupSession`, `InboundGroupSession` through the hook.
   - Pickle each, then call `from_pickle(blob, passphrase, **extra_kwargs)` where `extra_kwargs` is the *exact set of keyword arguments mautrix.crypto passes internally*. The kwargs are discovered by grep through mautrix source during implementation, not guessed.
   - Catches: future signature drift on `from_pickle`.

3. **`PkSigning` round-trip via mautrix**
   - Use the actual `mautrix.crypto` cross-signing entry point (specific module/function confirmed during implementation by reading mautrix source — likely `mautrix.crypto.cross_signing_key`) to sign a canonical-JSON payload.
   - Verify the returned signature with our own `fresholm.compat.olm.ed25519_verify`.
   - Catches: signature format / return-type drift between what mautrix expects and what we return.

4. **`OlmMachine` smoke construction**
   - Instantiate `mautrix.crypto.OlmMachine` with our `MemoryCryptoStore` and the minimum required collaborators (mock client + state-store stubs as needed).
   - Don't run a full Matrix sync. Verify only that the constructor and any `__post_init__` paths complete without raising.
   - Async test (`asyncio_mode = "auto"` is already set in `pyproject.toml`).
   - Catches: `MemoryCryptoStore` interface drift relative to what mautrix's `CryptoStore` protocol requires.

### Explicit non-scenarios

- No mock Matrix homeserver.
- No actual encrypted message sync.
- No bridge-layer code (those tests live downstream).

### README update

Two-line edit to the Development section:

- Recommended install becomes `pip install -e ".[dev]"`.
- One-line note that the dev extra includes `mautrix[e2be]` for integration tests.

## Section 3 — Vodozemac KDF investigation note

Not implementation. A research deliverable that informs a future PR.

### Output

`docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md` containing:

1. What `vodozemac::olm::AccountPickle::encrypt(&[u8; 32])` (and the matching `SessionPickle`, `OutboundGroupSessionPickle`, `InboundGroupSessionPickle`) actually does with the 32-byte input — direct AES key, or KDF-then-AES.
2. The cipher mode and authentication tag (AES-256-CBC + HMAC? AES-GCM? other?).
3. Whether the encrypted output format contains a salt or version byte that would let a future KDF change be backward-compatible without forcing all users to re-pickle.
4. **Verdict line** — exactly one of:
   - **(a)** Real weakness — `passphrase_to_key` should be replaced with PBKDF2 or Argon2id.
   - **(b)** Moot wrapper — vodozemac already applies an internal KDF; current code is fine; only a docstring clarification is needed.
   - **(c)** Mixed — partial protection; spell out exactly where the gap is.

### Method

Read the vodozemac 0.9 source — primarily wherever `pickle_*` / `*Pickle` types live (likely `src/utilities/mod.rs` and per-type pickle modules). Source is available locally in the cargo registry after build, or readable on docs.rs / the matrix-org/vodozemac repo. No web access required.

### Out of scope for this session

- Any code change to `passphrase_to_key`.
- Any backward-compat or migration plan.
- Bumping fresholm to 0.3.0.

## Architecture / Components Summary

Three units, each independent:

| Unit | Files touched | Risk | Reviewable in isolation |
|------|---------------|------|------------------------|
| License | `LICENSE` (new), `pyproject.toml` | None | Yes |
| Mautrix integration test | `pyproject.toml`, `tests/test_mautrix_integration.py` (new), CI workflow, `README.md` | Low — additive, self-skipping | Yes |
| Vodozemac KDF note | `docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md` (new) | None | Yes |

No shared state, no shared interfaces, no ordering constraint between units.

## Testing Strategy

- **Unit 1 (License)** — verify by `python -m build --sdist` and inspecting `PKG-INFO`.
- **Unit 2 (Mautrix test)** — the unit *is* the test. Verify by:
  - `pip install -e ".[dev]"` succeeds.
  - `pytest tests/test_mautrix_integration.py` passes.
  - Temporarily reverting commit `4058c6c` causes scenario 2 to fail (smoke check that the regression test actually catches the regression).
  - On a fresh install without `[dev]`, `pytest tests/test_mautrix_integration.py` reports the file as skipped, not errored.
- **Unit 3 (Investigation note)** — no code; verification is human review of the verdict.

## Error Handling

N/A for license. For mautrix integration test:

- Test failures should produce diffs / asserts that point at the offending compat-layer call, not raw mautrix tracebacks. Use targeted `assert` statements per scenario rather than relying on mautrix raising.
- The async `OlmMachine` test must close any opened resources in a fixture teardown to avoid leaking between tests.

## Open Questions / Implementation-Time Decisions

These are deliberately deferred to implementation, not blocking on this design:

1. Exact mautrix version floor (`>=0.20` is a placeholder; pin to the lowest version exposing all four scenarios' API surface).
2. Exact mautrix module to use for scenario 3 (`mautrix.crypto.cross_signing_key` is the leading candidate; confirm by reading mautrix source).
3. Exact set of kwargs to test in scenario 2 — discovered by grep through mautrix source, not guessed.
4. Which CI matrix entry hosts the `[dev]` install (likely Ubuntu + Python 3.12; confirm in CI config).
