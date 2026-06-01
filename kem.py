"""KEM dispatcher: use real Kyber if available, else fallback to kem_stub.

This module supports being imported as a top-level module (for pytest)
or as a package submodule. It first tries to load `kem_kyber`, then
falls back to `kem_stub` using both relative and absolute imports.
"""
impl = None
try:
    from . import kem_kyber as impl
except Exception:
    try:
        import kem_kyber as impl
    except Exception:
        impl = None

if impl is None:
    raise ImportError("No KEM backend found. Strict mode requires a true PQC backend (kem_kyber).")

def keygen(*args, **kwargs):
    return impl.keygen(*args, **kwargs)

def enc(pk, k_seed=None):
    # accept optional k_seed for compatibility with stub
    try:
        return impl.enc(pk, k_seed)
    except TypeError:
        # impl.enc may ignore k_seed
        return impl.enc(pk)

def dec(sk, C):
    return impl.dec(sk, C)

__all__ = ["keygen", "enc", "dec"]
