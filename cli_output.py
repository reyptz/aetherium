"""Helpers partagés pour l'affichage des démonstrations Aetherium."""

from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from typing import Iterator

WIDTH = 72


def _ensure_utf8_stdout() -> None:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


_ensure_utf8_stdout()


def banner(title: str, subtitle: str = "", width: int = WIDTH) -> None:
    print("═" * width)
    print(f"  {title}")
    if subtitle:
        print(f"  {subtitle}")
    print("═" * width)


def separator(title: str = "", width: int = WIDTH) -> None:
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * (width - pad - len(title) - 2)}")
    else:
        print("─" * width)


def info(label: str, value: str, indent: int = 2) -> None:
    print(f"{' ' * indent}{label:<18} {value}")


def fmt_bytes(label: str, data: bytes, secret: bool = False, verbose: bool = False) -> None:
    if secret:
        preview = "[PRIVÉE — non affichée]"
    elif verbose:
        preview = data.hex()
    else:
        preview = data.hex()[:48] + ("..." if len(data.hex()) > 48 else "")
    info(label, preview)


def fmt_size(label: str, nbytes: int) -> None:
    info(label, f"{nbytes} octets ({nbytes * 8} bits)")


@contextmanager
def timed_phase(name: str, verbose: bool = False) -> Iterator[None]:
    if not verbose:
        yield
        return
    start = time.perf_counter()
    yield
    elapsed_ms = (time.perf_counter() - start) * 1000
    info(f"[timing] {name}", f"{elapsed_ms:.2f} ms")


def summary_line(ok: bool, label: str) -> None:
    mark = "✓" if ok else "✗"
    print(f"  {mark} {label}")


def backends_status(kyber_available: bool, numpy_available: bool = True) -> None:
    kem = "ML-KEM Kyber512 (pqcrypto)" if kyber_available else "Stub HMAC-SHA256 [DEMO]"
    numpy = "numpy installé" if numpy_available else "numpy absent"
    info("Backend KEM", kem)
    info("Lattice demo", numpy)


def print_actions_help() -> None:
    print("\n  Actions disponibles :")
    info("kem", "KEM hybride canonique (aetherium.py)")
    info("chiffrement", "Simulation LWE / lattice thermodynamique")
    info("suite", "Générateur de clés + KEM Ultra + suite PQC")
    info("all", "Enchaîne les trois démonstrations")
    print()
