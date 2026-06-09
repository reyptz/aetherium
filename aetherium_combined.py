#!/usr/bin/env python3
"""
Point d'entrée unifié Aetherium.

Route les démonstrations vers les modules spécialisés :
  - kem         : KEM hybride canonique (aetherium.py)
  - chiffrement : simulation LWE / lattice (chiffrement.py)
  - suite       : générateur de clés + KEM Ultra + suite PQC
  - all         : enchaîne les trois démonstrations
"""

from __future__ import annotations

import argparse
import sys

from cli_output import backends_status, banner, print_actions_help, separator

try:
    import numpy  # noqa: F401
    _NUMPY_AVAILABLE = True
except ImportError:
    _NUMPY_AVAILABLE = False


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aetherium — démonstrations cryptographiques hybrides",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  python aetherium_combined.py --action all\n"
            "  python aetherium_combined.py --action kem -v\n"
            "  python aetherium_combined.py --action chiffrement\n"
        ),
    )
    parser.add_argument(
        "--action",
        choices=["kem", "chiffrement", "suite", "all"],
        default="all",
        help="démonstration à exécuter (défaut : all)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="affichage détaillé (hex complets, timings, métadonnées)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="liste les actions disponibles et quitte",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.list:
        banner("AETHERIUM — Actions disponibles")
        print_actions_help()
        return 0

    from aetherium import _KYBER_AVAILABLE, main as kem_demo
    from chiffrement import run_demo as chiffrement_demo
    from combined_crypto import run_suite_demo

    banner("AETHERIUM — Lanceur de démonstrations")
    backends_status(_KYBER_AVAILABLE, _NUMPY_AVAILABLE)
    info_action = args.action
    from cli_output import info
    info("Action", info_action)
    info("Verbose", "oui" if args.verbose else "non")
    print()

    demos = {
        "kem": ("KEM hybride canonique", kem_demo),
        "chiffrement": ("Simulation LWE", chiffrement_demo),
        "suite": ("Suite combinée", run_suite_demo),
    }

    if args.action == "all":
        for key in ("kem", "chiffrement", "suite"):
            label, fn = demos[key]
            separator(f"DÉMO : {label.upper()}")
            fn(verbose=args.verbose)
    else:
        label, fn = demos[args.action]
        fn(verbose=args.verbose)

    return 0


if __name__ == "__main__":
    sys.exit(main())
