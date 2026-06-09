import numpy as np

from cli_output import banner, info, separator, summary_line, timed_phase

# ---------- Paramètres thermodynamiques ----------
n = 256           # dimension du réseau
q = 3329          # module (corps fini)
sigma = 2.0       # écart-type du bruit thermique (racine de kT/2π)
T = 2 * np.pi * sigma**2   # température effective (kB=1)


def discrete_gaussian(sigma, size):
    """Échantillonne une gaussienne discrète centrée sur Z^n."""
    x = np.random.normal(0, sigma / np.sqrt(2 * np.pi), size=size)
    x = np.round(x).astype(int)
    return x


def encode_bit(b):
    """Encode un bit en un vecteur d'énergie."""
    mu = (b * (q // 2)) % q
    return mu


def decode_bit(mu_noisy):
    """Décode un bit à partir d'un scalaire bruité."""
    d0 = min(mu_noisy, q - mu_noisy)
    d1 = min(abs(mu_noisy - q // 2), q - abs(mu_noisy - q // 2))
    return 0 if d0 < d1 else 1


def keygen():
    A = np.random.randint(0, q, size=(n, n))
    s = discrete_gaussian(sigma, n) % q
    e = discrete_gaussian(sigma, n) % q
    t = (A @ s + e) % q
    return (A, t), s


def encrypt(pk, bit):
    A, t = pk
    r = discrete_gaussian(sigma, n) % q
    e1 = discrete_gaussian(sigma, n) % q
    e2 = discrete_gaussian(sigma, 1)[0] % q

    u = (A.T @ r + e1) % q
    mu = encode_bit(bit)
    v = (t @ r + e2 + mu) % q
    return (u, v)


def decrypt(sk, ciphertext):
    s = sk
    u, v = ciphertext
    mu_noisy = (v - s @ u) % q
    return decode_bit(mu_noisy)


def run_demo(verbose: bool = False) -> None:
    banner(
        "SIMULATION CHIFFREMENT LATTICE (Learning With Errors)",
        "Modèle thermodynamique : injection d'énergie + filtrage bruité",
    )
    info("Dimension (n)", str(n))
    info("Module (q)", str(q))
    info("σ (bruit)", f"{sigma}")
    info("Température T", f"{T:.2f} (kB=1)")

    separator("Génération des clés LWE (thermalisation)")
    with timed_phase("keygen", verbose):
        pk, sk = keygen()
    A, t = pk
    info("Matrice A", f"{A.shape[0]}×{A.shape[1]} — éléments ∈ [0, {q})")
    info("Vecteur t", f"longueur {len(t)}")
    if verbose:
        info("Aperçu A[0,:8]", " ".join(str(x) for x in A[0, :8]))
        info("Aperçu t[:8]", " ".join(str(x) for x in t[:8]))
        info("Aperçu sk[:8]", " ".join(str(x) for x in sk[:8]))

    separator("Transmission et déchiffrement")
    sequence = [0, 1, 0, 1, 1, 0, 1, 0, 1, 1]
    successes = 0
    for i, bit in enumerate(sequence):
        with timed_phase(f"bit {i}", verbose):
            c = encrypt(pk, bit)
            decrypted = decrypt(sk, c)
        ok = decrypted == bit
        successes += int(ok)
        status = "✓ SUCCÈS" if ok else "✗ ÉCHEC"
        line = f"Bit {bit} → déchiffré {decrypted} [{status}]"
        if verbose:
            u, v = c
            line += f"  |  ‖u‖₁={int(np.sum(np.abs(u)))}  v={int(v)}"
        info(f"[{i + 1}/{len(sequence)}]", line)

    rate = successes / len(sequence) * 100
    summary_line(successes == len(sequence), f"Taux de succès : {successes}/{len(sequence)} ({rate:.0f} %)")

    separator("Évaluation de l'entropie")
    s_entropy = -np.sum(np.log(np.abs(sk) + 1e-9))
    info("Entropie clé privée (proxy)", f"{s_entropy:.2f} nats")
    info("Bits transmis", str(len(sequence)))

    print("\n" + "═" * 72)
    print("  FIN — Simulation LWE")
    print("═" * 72 + "\n")


if __name__ == "__main__":
    run_demo()
