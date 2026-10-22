"""KEM dispatcher: ML-KEM-1024 only, fail-closed.

The real backend (`kem_kyber`, ML-KEM-1024 via pqcrypto) is required.
The insecure test double `kem_stub` is loaded ONLY when the environment
variable AETHERIUM_ALLOW_STUB=1 is set. Without a real backend and without
that opt-in, importing this module raises ImportError: Aetherium never
silently downgrades to a backend that offers no confidentiality.

This module supports being imported as a top-level module (for pytest)
or as a package submodule.
"""
import os
import warnings

impl = None
try:
    from . import kem_kyber as impl
except Exception:
    try:
        import kem_kyber as impl
    except Exception:
        impl = None

if impl is None:
    if os.environ.get("AETHERIUM_ALLOW_STUB") != "1":
        raise ImportError(
            "No ML-KEM-1024 backend found. Install pqcrypto "
            "(`pip install pqcrypto`). For tests only, set "
            "AETHERIUM_ALLOW_STUB=1 to use the insecure stub."
        )
    try:
        from . import kem_stub as impl
    except Exception:
        import kem_stub as impl
    warnings.warn(
        "Aetherium is using kem_stub: NO confidentiality. Tests only.",
        RuntimeWarning,
        stacklevel=2,
    )

BACKEND = impl.__name__.rsplit(".", 1)[-1]
IS_STUB = BACKEND == "kem_stub"


def keygen(*args, **kwargs):
    return impl.keygen(*args, **kwargs)


def enc(pk, k_seed=None):
    # accept optional k_seed for compatibility with stub
    try:
        return impl.enc(pk, k_seed)
    except TypeError:
        return impl.enc(pk)


def dec(sk, C):
    return impl.dec(sk, C)


__all__ = ["keygen", "enc", "dec", "BACKEND", "IS_STUB"]
