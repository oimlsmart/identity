"""The OIML SMART Identity Python SDK (auto-generated).

The typed client for the OIDC Provider at id.oimlsmart.org.
"""
from .client import IdentityClient

__version__ = "1.0.0-edition1"

__all__ = ["IdentityClient"]

def __getattr__(name: str):
    # The DPoP middleware (RFC 9449) is the optional extra — the import
    # raises the honest error when 'cryptography' is absent.
    if name in ("DpopAuth", "DpopKeys", "mint_dpop_proof"):
        from . import _dpop
        return getattr(_dpop, name)
    raise AttributeError(name)
