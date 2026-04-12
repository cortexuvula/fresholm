"""SAS verification for Matrix E2EE."""

import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class OlmSasError(Exception):
    pass

class Sas:
    def __init__(self, other_users_pubkey=None):
        self._private_key = X25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._shared_secret = None
        self.other_key_set = False
        if other_users_pubkey:
            self.set_their_pubkey(other_users_pubkey)

    @property
    def pubkey(self):
        raw = self._public_key.public_bytes_raw()
        return base64.b64encode(raw).rstrip(b"=").decode("ascii")

    def set_their_pubkey(self, key):
        key_b64 = key + "=" * (-len(key) % 4)
        their_bytes = base64.b64decode(key_b64)
        their_key = X25519PublicKey.from_public_bytes(their_bytes)
        self._shared_secret = self._private_key.exchange(their_key)
        if self._shared_secret == b"\x00" * 32:
            raise OlmSasError("Non-contributory ECDH exchange")
        self.other_key_set = True

    def _check(self):
        if not self.other_key_set:
            raise OlmSasError("Their public key has not been set")

    def _hkdf(self, info_bytes, length):
        """HKDF-SHA256 with salt=None, IKM=shared_secret, info=info_bytes."""
        hkdf = HKDF(algorithm=SHA256(), length=length, salt=None, info=info_bytes)
        return hkdf.derive(self._shared_secret)

    def generate_bytes(self, extra_info, length):
        self._check()
        if isinstance(extra_info, str):
            extra_info = extra_info.encode("utf-8")
        return self._hkdf(extra_info, length)

    def calculate_mac(self, message, extra_info):
        self._check()
        if isinstance(extra_info, str):
            extra_info = extra_info.encode("utf-8")
        if isinstance(message, str):
            message = message.encode("utf-8")
        mac_key = self._hkdf(extra_info, 32)
        h = HMAC(mac_key, SHA256())
        h.update(message)
        return base64.b64encode(h.finalize()).rstrip(b"=").decode("ascii")

    def calculate_mac_long_kdf(self, message, extra_info):
        self._check()
        if isinstance(extra_info, str):
            extra_info = extra_info.encode("utf-8")
        if isinstance(message, str):
            message = message.encode("utf-8")
        mac_key = self._hkdf(extra_info, 256)  # 256 bytes, not 32
        h = HMAC(mac_key, SHA256())
        h.update(message)
        return base64.b64encode(h.finalize()).rstrip(b"=").decode("ascii")
