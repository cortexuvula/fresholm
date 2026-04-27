"""Hook to make ``import olm`` resolve to fresholm's compatibility layer.

Usage::

    import fresholm.import_hook  # noqa: F401  -- side-effect import
    import olm  # now uses fresholm.compat.olm

Also stubs the ``_libolm`` CFFI module that python-olm exposes. mautrix.crypto
does ``from _libolm import ffi, lib`` at import time, so without a stub
``import mautrix.crypto`` raises ``ModuleNotFoundError``. The stub provides
``ffi = None`` and ``lib = None``, which is enough for module-load-time imports
to succeed BUT WILL CRASH if any mautrix code path actually invokes ffi or lib
methods (e.g. ``mautrix.crypto.Session.describe()`` calls ``lib.olm_session_describe``).

This is a deliberate minimum-viable shim: it unblocks integration tests that
only exercise import-time behavior and the python-level compat surface
(`Account.from_pickle`, `PkSigning`, etc.). Building a real CFFI shim that
delegates to fresholm's compat layer would be a substantially larger
undertaking and is out of scope here.
"""

import sys
from types import ModuleType

import fresholm.compat.olm as _olm_compat

sys.modules["olm"] = _olm_compat

_libolm_stub = ModuleType("_libolm")
_libolm_stub.ffi = None
_libolm_stub.lib = None
sys.modules["_libolm"] = _libolm_stub
