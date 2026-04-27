# Vodozemac Pickle KDF Investigation

**Date:** 2026-04-27
**Source:** vodozemac 0.9.0 (path: `/Users/cortexuvula/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/vodozemac-0.9.0`)
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

The call chain for `AccountPickle::encrypt(pickle_key: &[u8; 32])` is:

1. `AccountPickle::encrypt` (`src/olm/account/mod.rs:580`) calls
   `pickle(&self, pickle_key)` from `src/utilities/mod.rs:61`.
2. `pickle()` (`src/utilities/mod.rs:67`) calls
   `Cipher::new_pickle(pickle_key)` from `src/cipher/mod.rs:141`.
3. `Cipher::new_pickle` (`src/cipher/mod.rs:141`) calls
   `CipherKeys::new_pickle(key)` from `src/cipher/key.rs:82`.
4. `CipherKeys::new_pickle` (`src/cipher/key.rs:82`) calls
   `ExpandedKeys::new_pickle(pickle_key)` from `src/cipher/key.rs:45`.
5. `ExpandedKeys::new_pickle` (`src/cipher/key.rs:45`) calls
   `Self::new_helper(pickle_key, b"Pickle")` from `src/cipher/key.rs:49`.
6. `new_helper` (`src/cipher/key.rs:49–58`) runs:
   ```rust
   let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), message_key);
   hkdf.expand(info, &mut expanded_keys)  // info = b"Pickle", output = 80 bytes
   ```
   The 80-byte output is split as: bytes 0–31 → AES-256 key, bytes 32–63 → HMAC-SHA-256
   key, bytes 64–79 → AES-256-CBC IV (src/cipher/key.rs:93–95).
7. Back in `cipher/mod.rs:254–261`, `encrypt_pickle` runs AES-256-CBC encryption then
   appends a truncated (8-byte) HMAC-SHA-256 MAC over the ciphertext.
8. The result is base64-encoded with no padding and returned as a `String`
   (`src/utilities/mod.rs:73`).

The five required answers:

1. **Direct cipher key, or KDF-then-key?** HKDF — vodozemac applies `HKDF-SHA-256` with
   a fixed salt of `[0]` and info string `"Pickle"` to the 32 bytes before deriving the
   AES key, HMAC key, and IV (`src/cipher/key.rs:52–56`).
2. **Cipher mode:** AES-256-CBC + HMAC-SHA-256 (truncated to 8 bytes, appended after
   ciphertext) — `src/cipher/mod.rs:254–261` and `src/cipher/mod.rs:163–165,173–183`.
3. **Is there a salt in the output?** No. The HKDF salt `[0]` is a fixed, hardcoded
   single zero byte (`src/cipher/key.rs:52`). It is not stored in the output and is
   identical for every pickle regardless of the passphrase.
4. **Is there a version byte / format header?** No. The native vodozemac pickle (the path
   used by `AccountPickle::encrypt`) goes through `pickle()` in
   `src/utilities/mod.rs:61–74`, which prepends nothing. The output is purely
   `base64(AES-256-CBC-ciphertext ‖ 8-byte-HMAC)`. The `libolm_compat` path (a separate
   feature flag) does prepend a 4-byte big-endian version number, but fresholm does not
   use that path.
5. **Does the format support backward-compatible KDF migration?** No. Because there is no
   version byte and no stored salt, a decoder cannot distinguish a blob produced with the
   current passphrase-copy scheme from one produced with a proper password-based KDF. Any
   migration must be signaled out-of-band (e.g., a new API method, an application-level
   version field, or a new blob prefix).

## Verdict

**(a) Real weakness.** vodozemac uses the 32 bytes directly as the HKDF input key
material with no internal password-stretching KDF. HKDF-SHA-256 with a fixed salt is a
key-derivation function for high-entropy secrets, not a password-based KDF — it applies
exactly one round of HMAC, which is computationally trivial. A 1-character ASCII
passphrase becomes a 32-byte buffer with 31 known-zero bytes (set by `passphrase_to_key`,
`account.rs:12–15`), so brute-force cost is governed solely by the entropy of the
passphrase character, not by any work factor. Replace `passphrase_to_key` with
PBKDF2-HMAC-SHA-256 (200k+ iterations, NIST SP 800-132) or Argon2id. Because the current
format has no version byte or stored salt, migration requires an explicit versioning
strategy.

## Recommended next steps

1. **Choose a password hashing scheme.** Argon2id is preferred (memory-hard); PBKDF2-
   HMAC-SHA-256 at ≥ 200 000 iterations is the minimum acceptable alternative.
   Add `argon2` or `pbkdf2` to `crates/vodozemac-python/Cargo.toml`.

2. **Define a new blob prefix.** Prefix every freshly encrypted pickle with a 1-byte
   version tag: `0x01` = legacy (current zero-padded passphrase), `0x02` = Argon2id with
   embedded salt. Store the Argon2id parameters (memory, time, parallelism) and a 16-byte
   random salt immediately after the version byte, before the vodozemac-produced
   ciphertext.

3. **Implement `passphrase_to_key_v2(passphrase: &[u8]) -> [u8; 32]`** in `account.rs`
   that runs Argon2id with the generated salt and returns the 32-byte derived key, which
   is then passed to `AccountPickle::encrypt` as before (vodozemac's own HKDF-SHA-256
   expansion still runs on top, which is fine).

4. **Keep dual-decode for one release window.** On decrypt, read the first byte: if `0x01`
   fall back to the legacy `passphrase_to_key` path; if `0x02` use the new path. Emit a
   deprecation warning on the legacy path.

5. **Document as a 0.3.0 breaking change.** Blobs produced by 0.2.x are readable by
   0.3.x for one release window but not vice versa. After one release, remove the legacy
   decode path in 0.4.0.

6. **Update all five call sites.** `account.rs:113,120`, `session.rs:89,96`,
   `group_session.rs:45,52`, and `inbound_group_session.rs:72,79` all share the same
   `passphrase_to_key` call. They must all be migrated consistently.

7. **Add a test** that verifies a 1-character passphrase under the new scheme produces a
   different 32-byte key material for every call (i.e., the salt is random and
   serialized), and that a round-trip through `from_encrypted_string` succeeds.
