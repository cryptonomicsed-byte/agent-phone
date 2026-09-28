"""pytest configuration for agent-phone tests.

- Adds the sibling minipae directory to sys.path (it is not pip-installed).
- Installs a minimal RNS stub so tests that don't exercise Reticulum can
  import agent_phone without a live RNS install.  test_reticulum.py skips
  itself with pytest.importorskip("RNS") when the real RNS is absent.
"""
import sys
import types
import pathlib

# Make minipae importable from its sibling repo directory.
_minipae_path = str(pathlib.Path(__file__).resolve().parents[2] / "minipae")
if _minipae_path not in sys.path:
    sys.path.insert(0, _minipae_path)

# Stub RNS only if the real package is not installed — real RNS is needed by
# test_reticulum.py; if it's missing, those tests will skip themselves.
try:
    import RNS  # noqa: F401
except ModuleNotFoundError:
    _rns = types.ModuleType("RNS")

    class _Destination:
        IN = 0
        SINGLE = 1

    class _Identity:
        KEYSIZE = 512
        hexhash = "stub" * 8

        @classmethod
        def from_bytes(cls, _b):
            return cls()

    class _Reticulum:
        def __init__(self, _config=None):
            pass

    _rns.Identity = _Identity
    _rns.Destination = _Destination
    _rns.Reticulum = _Reticulum
    sys.modules["RNS"] = _rns

    # LXMF stub (imported by reticulum.py)
    _lxmf = types.ModuleType("LXMF")
    _lxmf.LXMRouter = object
    _lxmf.LXMessage = object
    sys.modules["LXMF"] = _lxmf
