"""Import hook that makes ``import olm`` resolve to fresholm's compat layer.

Usage::

    import fresholm.import_hook  # noqa: F401  -- side-effect import
    import olm  # now uses fresholm.compat.olm
"""

import sys

import fresholm.compat.olm as _olm_compat

sys.modules["olm"] = _olm_compat
