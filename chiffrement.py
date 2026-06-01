import numpy as np
import hashlib

# ---------- Paramètres thermodynamiques ----------
n = 256           # dimension du réseau
q = 3329          # module (corps fini)
sigma = 2.0       # écart-type du bruit thermique (racine de kT/2π)
T = 2 * np.pi * sigma**2   # température effective (kB=1)

# ---------- Distribution de Gibbs discrète ----------
def discrete_gaussian(sigma, size):
    """Échantillonne une gaussienne discrète centrée sur Z^n."""
    # Méthode de rejet basée sur la distribution continue
    # P(x) ∝ exp(-π ||x||²/σ²)
    x = np.random.normal(0, sigma / np.sqrt(2 * np.pi), size=size)
    x = np.round(x).astype(int)  # discrétisation par arrondi
    return x

# ---------- Fonction d'encodage/décodage ----------
def encode_bit(b):
    """Encode un bit en un vecteur d'énergie."""
    mu = (b * (q // 2)) % q
    return mu

def decode_bit(mu_noisy):
    """Décode un bit à partir d'un scalaire bruité."""
    # Distance aux centres 0 et q/2
    d0 = min(mu_noisy, q - mu_noisy)  # distance à 0 modulo q
    d1 = min(abs(mu_noisy - q//2), q - abs(mu_noisy - q//2))
    return 0 if d0 < d1 else 1

# ---------- Génération de clés (thermalisation) ----------
def keygen():
    A = np.random.randint(0, q, size=(n, n))       # matrice aléatoire
    s = discrete_gaussian(sigma, n) % q             # secret pur
    e = discrete_gaussian(sigma, n) % q             # bruit thermique
    t = (A @ s + e) % q                             # état bruité = clé publique
    return (A, t), s

# ---------- Chiffrement (injection d'énergie) ----------
def encrypt(pk, bit):
    A, t = pk
    r = discrete_gaussian(sigma, n) % q             # vecteur aléatoire (agitation)
    e1 = discrete_gaussian(sigma, n) % q
    e2 = discrete_gaussian(sigma, 1)[0] % q

    u = (A.T @ r + e1) % q
    mu = encode_bit(bit)
    v = (t @ r + e2 + mu) % q
    return (u, v)

# ---------- Déchiffrement (filtrage thermique) ----------
def decrypt(sk, ciphertext):
    s = sk
    u, v = ciphertext
    mu_noisy = (v - s @ u) % q
    return decode_bit(mu_noisy)

# ========== Démonstration ==========
if __name__ == "__main__":
    print("═" * 72)
    print("  SIMULATION CHIFFREMENT LATTICE (Learning With Errors)")
    print("═" * 72)
    print(f"  Paramètres : dimension (n) = {n}, module (q) = {q}")
    print(f"  Température effective (T)  = {T:.2f} (kB=1)")
    print("\n  [+] Génération des clés LWE (Thermalisation)...")
    pk, sk = keygen()
    print("      > Clé publique A (Matrice n x n) générée.")
    print(f"      > Vecteur bruit thermique injecté (écart-type σ={sigma}).")

    print("\n  [+] Transmission et Déchiffrement de la séquence")
    for bit in [0, 1, 0, 1, 1]:
        c = encrypt(pk, bit)
        decrypted = decrypt(sk, c)
        status = "✓ SUCCÈS" if decrypted == bit else "✗ ÉCHEC"
        print(f"      Bit {bit} → Injecté dans (u,v) → Filtré: {decrypted} [{status}]")

    print("\n  [+] Évaluation de l'Entropie")
    s_entropy = -np.sum(np.log(np.abs(sk) + 1e-9))  # proxy grossier
    print(f"      Entropie de la clé privée (proxy) : {s_entropy:.2f} nats")
    print("═" * 72 + "\n")