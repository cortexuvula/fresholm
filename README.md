# fresholm

Drop-in replacement for `python-olm` backed by vodozemac (Rust) for mautrix Matrix bridge E2EE.

## Why?

| Library | Status |
|---|---|
| `python-olm` | Archived; fails to build on macOS ARM64 / Xcode 16+ / CMake 3.28+ |
| `libolm` (C) | Deprecated by the Matrix.org Foundation in favour of vodozemac |
| `vodozemac-bindings` | Officially marked "no longer actively maintained" |
| `mautrix-python` | Still hard-depends on `python-olm` for the `e2be` extra |

`fresholm` wraps vodozemac through PyO3/maturin and exposes a python-olm-compatible API so
mautrix bridges can drop it in with zero or minimal code changes.

## Install

```
pip install fresholm
```

Pre-built wheels are provided for macOS ARM64, Linux x86-64/aarch64, and Windows.

## Usage

### Import hook (zero-change migration)

Insert one import before any code that does `import olm`. It monkey-patches `sys.modules`
so that `import olm` resolves to fresholm's compatibility layer.

```python
import fresholm.import_hook  # noqa: F401 -- side-effect import
import olm  # now backed by fresholm
```

### Direct import

```python
from fresholm.compat.olm import (
    Account,
    Session,
    OutboundGroupSession,
    InboundGroupSession,
    OlmMessage,
    OlmPreKeyMessage,
    PkEncryption,
    PkDecryption,
    PkSigning,       # ed25519 cross-signing keys (mautrix.crypto)
    Sas,             # Short Authentication String verification
    sha256,          # SHA-256 hash (unpadded base64)
    ed25519_verify,  # Ed25519 signature verification
)
```

### Olm 1:1 encryption

```python
from fresholm.compat.olm import Account, OlmPreKeyMessage, Session

# --- Key exchange setup ---
alice = Account()
bob = Account()

bob.generate_one_time_keys(1)
bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
bob.mark_keys_as_published()

# --- Alice opens an outbound session to Bob ---
alice_session = alice.new_outbound_session(
    bob.identity_keys["curve25519"],
    bob_otk,
)

# Alice sends the first message (a pre-key message)
msg = alice_session.encrypt("Hello Bob!")
assert isinstance(msg, OlmPreKeyMessage)   # message_type == 0

# --- Bob creates an inbound session from Alice's pre-key message ---
bob_session = bob.new_inbound_session(
    alice.identity_keys["curve25519"],
    msg,
)

# Bob replies (normal message)
reply = bob_session.encrypt("Hello Alice!")
plaintext = alice_session.decrypt(reply)
assert plaintext == "Hello Alice!"

# --- Persist and restore a session ---
# .pickle() / .from_pickle() use vodozemac encrypted-string serialization,
# not Python's standard library pickle module.
blob = alice_session.pickle("my-passphrase")
restored = Session.from_pickle(blob, "my-passphrase")
assert restored.id == alice_session.id
```

### Megolm group encryption

```python
from fresholm.compat.olm import OutboundGroupSession, InboundGroupSession

# Sender creates a group session and shares the session key out-of-band
outbound = OutboundGroupSession()
session_key = outbound.session_key   # share this with recipients over Olm

# Each recipient constructs an inbound session from the shared key
inbound = InboundGroupSession(session_key)
assert inbound.id == outbound.id

# Encrypt and decrypt
ciphertext = outbound.encrypt("Hello room!")
plaintext, message_index = inbound.decrypt(ciphertext)
assert plaintext == "Hello room!"
assert message_index == 0

# Persist and restore
blob = outbound.pickle("room-passphrase")
restored = OutboundGroupSession.from_pickle(blob, "room-passphrase")
assert restored.id == outbound.id
```

## Compatibility notes

The compat layer (`fresholm.compat.olm`) matches the python-olm API as used by mautrix.

### mautrix.crypto support

`mautrix.crypto.cross_signing_key` and `mautrix.crypto.signature` require `olm.PkSigning`
and `olm.PkSigningError`. Both are provided by the compat layer:

```python
from fresholm.compat.olm import PkSigning, PkSigningError

seed = PkSigning.generate_seed()          # os.urandom(32)
signer = PkSigning(seed)
sig = signer.sign("canonical json")       # unpadded base64 Ed25519 signature
pub = signer.public_key                   # unpadded base64 Ed25519 public key
```

`olm.Sas` (Short Authentication String) is also implemented for emoji/decimal verification,
using pure Python (X25519 ECDH + HKDF-SHA256). No C library dependency.

- **Properties, not methods** -- `account.identity_keys`, `session.id`,
  `outbound.session_key`, `outbound.message_index`, `inbound.first_known_index` are
  all properties, consistent with python-olm.
- **Subclassable** -- `from_pickle` uses `cls.__new__(cls)`, so subclasses are preserved
  through serialisation round-trips.
- **String passphrases** -- `pickle()` and `from_pickle()` accept `str` or `bytes`
  passphrases (python-olm accepted only `bytes`).
- **Import hook** -- `import fresholm.import_hook` registers `olm` in `sys.modules`;
  no source edits needed in the consuming library.

Note: despite the method name, `pickle()` and `from_pickle()` do **not** use Python's
standard library `pickle` module. They call vodozemac's own encrypted-string
serialization, which is safe to use with untrusted data.

## Pickle format

`pickle()` / `from_pickle()` switched to an Argon2id-stretched envelope in 0.3.0
(output prefixed `v2|`, with a per-pickle 16-byte salt; RFC 9106 second-recommended
profile). Blobs produced by 0.2.x still load on 0.3.x but emit a `DeprecationWarning`;
v1 read support will be removed in 0.4.0. The format break is forward-only —
0.2.x cannot read v2 blobs, so once you re-pickle there is no downgrade path.

## Known differences from python-olm / libolm

- **Serialisation format is incompatible.** Sessions serialized by libolm/python-olm
  cannot be loaded by fresholm, and vice-versa. Both sides must re-generate sessions.
- **No `_libolm` FFI.** Code that imports `olm._libolm` or calls C-level symbols
  directly will break. The compat shim covers the public Python API only.

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

Rust toolchain 1.75+ is required. Install via [rustup](https://rustup.rs).

## License

MIT
