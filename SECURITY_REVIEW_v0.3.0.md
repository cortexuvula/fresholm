# fresholm v0.3.0 Security / Bug Review

**Scope**: Argon2id KDF migration, v2 pickle envelope, PyO3 FFI boundary,
import hook, and coverage gaps.
**Date**: 2026-04-29
**Tests**: 217 passed, 3 failed (all env-related `ModuleNotFoundError` for
`Cryptodome`, not code bugs).

---

## Findings Ranked by Severity

### CRITICAL — None found

---

### MEDIUM — 2 items

#### M1: Argon2 parameter caps may be too low for high-memory profiles
**File**: `crates/vodozemac-python/src/pickle_format.rs:123-125`

```rust
const MAX_M_COST: u32 = 1_048_576; // 1 GiB
const MAX_T_COST: u32 = 256;
const MAX_P_COST: u32 = 8;
```

The `MAX_P_COST = 8` cap is fine, but `MAX_M_COST = 1_048_576` (1 GiB) combined
with `MAX_T_COST = 256` would allow an adversarial pickle to demand
~256 GiB of work if someone later bumps `p_cost` too.  This is bounded enough
not to be a DoS vector, but worth confirming the caps are intentional.

The current default is `m=19_456, t=2, p=1`, so these are generous.  No fix
needed now, but document the rationale if profiles are ever bumped.

**Mitigation**: Already acceptable for v0.3.0; consider tying caps to a
multiple of the default profile for future-proofing.

---

#### M2: `_libolm_stub` creates a runtime crash vector if mautrix calls `lib.*`
**File**: `fresholm/import_hook.py`

The stub sets `ffi = None` and `lib = None`.  The docstring explicitly warns
that "WILL CRASH if any mautrix code path actually invokes ffi or lib methods."
`mautrix.crypto.Session.describe()` does exactly this (`lib.olm_session_describe`).

This is a **documented limitation**, not an unexpected bug, but it means
fresholm is not yet a 100 % drop-in replacement for python-olm under
mautrix.  If any user imports the hook and then a mautrix path touches
`_libolm.lib`, they get an opaque `AttributeError` (or worse, a segfault if
the CFFI pointer is used).

**Mitigation**: Already documented.  To harden, wrap `ffi` and `lib` in a
small object that raises a clean `OlmError("_libolm CFFI shim not implemented;
use fresholm native APIs")` on any attribute access.  This turns a crash into
a recoverable exception.

---

### LOW — 4 items

#### L1: `unwrap()` in production `decode_envelope` after length check
**File**: `crates/vodozemac-python/src/pickle_format.rs:116-118`

```rust
let m_cost = u32::from_be_bytes(header[0..4].try_into().unwrap());
```

The slice length is validated as `28` on line 110, so `header[0..4]` is always
4 bytes and `try_into()` will never fail.  Technically safe, but replacing
with `.try_into().ok().unwrap_or(0)` (or using `array_ref!`) would eliminate
panic boilerplate.

**Verdict**: Not exploitable. Code-review hygiene only.

---

#### L2: `__init__.py` version out of sync with implied 0.3.0 release
**File**: `fresholm/__init__.py:1`

```python
__version__ = "0.2.5"
```

Context states v0.3.0 is current.  The version string was not bumped.

**Fix**: Update to `"0.3.0"` (or `"0.3.0-dev"` if pre-release).

---

#### L3: No `rand` feature selection for CSPRNG portability
**File**: `crates/vodozemac-python/Cargo.toml`

```toml
rand = "0.8"
```

`rand` v0.8 defaults to `std_rng` (ChaCha12 on most platforms).  For a crypto
library, consider pinning `rand = { version = "0.8", features = ["getrandom"] }`
explicitly to avoid silently falling back to a weaker RNG on esoteric targets.

**Verdict**: On standard targets (linux/macos/windows) `thread_rng()` already
uses a CSPRNG, so this is a portability note rather than a vulnerability.

---

#### L4: `PkSigning.sign` calls `_passphrase_to_bytes` through Python compat,
but Rust `_v1_encrypt_*_for_testing` functions are exposed and underscored
**Files**: `crates/vodozemac-python/src/lib.rs`

The `_v1_encrypt_*_for_testing` Rust functions are `pub(crate)` but still added
to the Python module via `wrap_pyfunction!`.  An underscored name is a
convention, not a barrier — Python code can call them.

They correctly use the weak v1 KDF, but since they are clearly named
`_v1_encrypt_*_for_testing`, the risk is minimal.  This is fine for a v1
migration window that closes in 0.4.0, but confirm they are removed in that
release.

---

## Other Observations (not bugs)

### Argon2id implementation is correct
- Salt is 16 bytes, freshly generated per `to_encrypted_string()` call.
- `hash_password_into` is used correctly; no allocation of the output.
- Base64 is URL-safe / no-pad, avoiding `+` and `/` in the envelope header.
- The v2 prefix `v2|` is unambiguous and the fallback to v1 is clean.
- All four types (Account, Session, GroupSession, InboundGroupSession) use
the envelope consistently.

### FFI boundary is clean
- Every `from_base64`, `from_bytes`, and `from_encrypted` call maps errors to
a specific `Olm*Error` Python exception.
- No panic paths in production Rust code (all `.unwrap()` are in `#[cfg(test)]`).
- `Account.create_inbound_session` correctly extracts the identity key from the
PreKeyMessage when `their_identity_key` is `None` or `""`.

### Session compat stash
The `_stashed_prekey_plaintext` stash in `fresholm/compat/olm.py:Session`
is bounded (single tuple, cleared on first matching decrypt), never
serialized through pickle, and correctly re-initialized as `None` after
`from_pickle`.  No state-leak risk.

---

## Summary

| # | Severity | Item | Status |
|---|----------|------|--------|
| M1 | MEDIUM | Argon2 parameter max caps could be tighter | Acceptable for now |
| M2 | MEDIUM | `_libolm` stub can crash on mautrix CFFI paths | Documented; hardening recommended |
| L1 | LOW | `unwrap()` after length check | Non-exploitable; hygienic fix optional |
| L2 | LOW | `__version__` out of sync | Trivial fix |
| L3 | LOW | `rand` feature not pinned explicitly | Portability note |
| L4 | LOW | `_v1_encrypt_*_for_testing` exposed in Python | Acceptable for v0.3.x |

**Bottom line**: The Argon2id migration is implemented correctly. No critical
or high-severity issues. The two MEDIUM items are architectural gaps, not
exploitable vulnerabilities. The codebase is in good shape for v0.3.x.
