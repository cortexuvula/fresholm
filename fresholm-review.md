# fresholm v0.2.0 Code Review

**Reviewer**: Frikkie  
**Date**: April 12, 2026  
**Repo**: github.com/cortexuvula/fresholm  
**Commits reviewed**: 6b47899..78cb04c (9 commits, +680 lines)

---

## Overall Verdict: Ship it after fixing one bug

Clean code, good test coverage, well-structured. One potential interop bug that needs fixing before release.

---

## What's Good

### InboundSession / OutboundSession
Clean thin subclasses delegating to Account's existing `new_inbound_session()` and `new_outbound_session()` methods. The Rust change to `create_inbound_session` accepting `Option<&str>` for identity_key is smart -- lets it extract the key from the pre-key message when not provided, matching python-olm behavior.

### Tests
Excellent coverage. The matrix-nio subclass pattern tests (`NioOutboundSession`, `NioInboundSession`) are exactly what you need to catch regressions before hitting nio in production. Full roundtrip tests for both Olm and Megolm are solid.

### ed25519_verify
Proper handling of both padded and unpadded base64. The `except InvalidSignature -> OlmVerifyError` conversion is correct. Garbage key test case is a nice edge case.

### sha256
Clean. Stripped base64 matches python-olm output. Handles str and bytes input.

### crypto_store fix
`_get_session_id()` helper that handles both native sessions (`.session_id()`) and compat sessions (`.id`) is a pragmatic solution.

### cryptography dependency
`cryptography>=41.0` in pyproject.toml is correct. It's already a transitive dep of matrix-nio via pycryptodome anyway, so no install friction.

---

## Bug: `calculate_mac_long_kdf` is wrong

**File**: `fresholm/compat/sas.py`, line 67

```python
mac_key = self._hkdf(extra_info, 256)  # 256 bytes, not 32
```

This is incorrect. The "long KDF" path in libolm does NOT use HKDF at all. Looking at libolm's `olm_sas_calculate_mac` C source:

- **Normal** (`calculate_mac`): HKDF(shared_secret, info, 32 bytes) -> HMAC-SHA256(mac_key, message)
- **Long KDF** (`calculate_mac_long_kdf`): HMAC-SHA256(shared_secret, message || extra_info) directly

The "long" in "long KDF" refers to using the raw 32-byte ECDH shared secret as the HMAC key without first deriving a shorter MAC key. The current implementation derives a 256-byte key via HKDF, which is neither correct.

### Fix

```python
def calculate_mac_long_kdf(self, message, extra_info):
    self._check()
    if isinstance(extra_info, str):
        extra_info = extra_info.encode("utf-8")
    if isinstance(message, str):
        message = message.encode("utf-8")
    # Legacy: HMAC-SHA256(shared_secret, message || extra_info)
    h = HMAC(self._shared_secret, SHA256())
    h.update(message + extra_info)
    return base64.b64encode(h.finalize()).rstrip(b"=").decode("ascii")
```

### Why tests don't catch this

Current tests pass because both sides use the same wrong derivation, so they produce matching outputs. But interop with python-olm/libolm clients will fail silently -- the MACs won't match when a legacy client uses `calculate_mac_long_kdf`. This matters for key verification with older Matrix clients.

---

## Minor Notes

1. **`_creation_plaintext` in InboundSession** (olm.py line 283) -- copying an attribute that doesn't exist on the parent Session. Harmless (`getattr` with None fallback), but dead code. Not a bug, just noise.

2. **sas.py line 67 comment** `# 256 bytes, not 32` will mislead future maintainers once the bug is fixed. Delete it.

3. **`sas.py` pubkey property** -- stripping `=` with `rstrip(b"=")` is fine and matches python-olm's convention. Consistent with the rest of the codebase.

4. **Import hook wiring** -- All new classes properly exported in `__all__` and imported in olm.py. `olm.InboundSession`, `olm.OutboundSession`, `olm.Sas`, `olm.sha256`, `olm.ed25519_verify`, `olm.utility`, and `olm.utility.OlmVerifyError` will all resolve correctly through `import fresholm.import_hook`.

---

## Summary

| Component | Status | Notes |
|-----------|--------|-------|
| InboundSession | OK | Clean delegation to Account |
| OutboundSession | OK | Clean delegation to Account |
| Sas.pubkey | OK | Correct unpadded base64 |
| Sas.set_their_pubkey | OK | Non-contributory ECDH check is nice |
| Sas.generate_bytes | OK | Raw extra_info to HKDF matches libolm |
| Sas.calculate_mac | OK | HKDF(32) + HMAC-SHA256 is correct |
| Sas.calculate_mac_long_kdf | **BUG** | Uses HKDF instead of raw shared secret |
| sha256 | OK | Clean |
| ed25519_verify | OK | Proper exception handling |
| Rust create_inbound_session | OK | Option<&str> is clean |
| Tests | OK | Excellent coverage |
| crypto_store fix | OK | Pragmatic _get_session_id helper |

**Action required**: Fix `calculate_mac_long_kdf`, then ready for PyPI release.
