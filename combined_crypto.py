"""
Modules combinés Aetherium : générateur de clés, KEM Ultra simulé, suite PQC.
Extrait de l'ancien aetherium_combined.py pour alléger le point d'entrée CLI.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from cli_output import banner, fmt_bytes, info, separator, summary_line, timed_phase

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives import constant_time as _ct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    _ct = None
    HKDF = None  # type: ignore
    default_backend = None  # type: ignore

try:
    from mnemonic import Mnemonic
    BIP39_AVAILABLE = True
except ImportError:
    BIP39_AVAILABLE = False


class KeyType(Enum):
    AES_128 = "aes128"
    AES_192 = "aes192"
    AES_256 = "aes256"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    RSA_2048 = "rsa2048"
    RSA_3072 = "rsa3072"
    RSA_4096 = "rsa4096"
    ECC_SECP256R1 = "ecc_secp256r1"
    ECC_SECP384R1 = "ecc_secp384r1"
    ECC_SECP521R1 = "ecc_secp521r1"
    ECC_SECP256K1 = "ecc_secp256k1"


class OutputFormat(Enum):
    PEM = "pem"
    DER = "der"
    RAW = "raw"
    HEX = "hex"
    BASE64 = "base64"
    JWK = "jwk"
    OPENSSH = "openssh"
    PKCS12 = "pkcs12"


@dataclass
class KeyGenerationConfig:
    key_type: KeyType
    output_format: OutputFormat = OutputFormat.PEM
    password: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    curve_name: Optional[str] = None
    key_size: Optional[int] = None
    passphrase: Optional[str] = None
    include_private: bool = True
    include_public: bool = True


@dataclass
class GeneratedKey:
    key_type: KeyType
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    certificate: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    generation_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    fingerprint: Optional[str] = None
    key_id: Optional[str] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class CryptographicKeyGenerator:
    def __init__(self):
        self.backend = default_backend() if CRYPTO_AVAILABLE else None

    def generate_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        if config.key_type in [KeyType.AES_128, KeyType.AES_192, KeyType.AES_256]:
            return self._generate_aes_key(config)
        elif config.key_type == KeyType.CHACHA20_POLY1305:
            return self._generate_chacha20_key(config)
        elif config.key_type in [KeyType.RSA_2048, KeyType.RSA_3072, KeyType.RSA_4096]:
            return self._generate_rsa_key(config)
        elif config.key_type in [KeyType.ECC_SECP256R1, KeyType.ECC_SECP384R1,
                                 KeyType.ECC_SECP521R1, KeyType.ECC_SECP256K1]:
            return self._generate_ecc_key(config)
        else:
            raise ValueError(f"Unsupported key type: {config.key_type}")

    def _generate_aes_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        sizes = {KeyType.AES_128: 16, KeyType.AES_192: 24, KeyType.AES_256: 32}
        key_size = sizes[config.key_type]
        key_bytes = secrets.token_bytes(key_size)
        if config.output_format == OutputFormat.HEX:
            key_str = key_bytes.hex()
        elif config.output_format == OutputFormat.BASE64:
            key_str = base64.b64encode(key_bytes).decode()
        else:
            key_str = key_bytes.hex()
        fingerprint = hashlib.sha256(key_bytes).hexdigest()
        return GeneratedKey(
            key_type=config.key_type,
            private_key=key_str if config.include_private else None,
            metadata={"key_size_bits": key_size * 8, "algorithm": "AES"},
            fingerprint=fingerprint,
            key_id=f"aes_{int(time.time())}",
        )

    def _generate_chacha20_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        key_bytes = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        key_data = {
            "key": base64.b64encode(key_bytes).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        }
        fingerprint = hashlib.sha256(key_bytes).hexdigest()
        return GeneratedKey(
            key_type=config.key_type,
            private_key=json.dumps(key_data) if config.include_private else None,
            metadata={"algorithm": "ChaCha20-Poly1305", "key_size_bits": 256},
            fingerprint=fingerprint,
            key_id=f"chacha20_{int(time.time())}",
        )

    def _generate_rsa_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Cryptography library missing")
        sizes = {KeyType.RSA_2048: 2048, KeyType.RSA_3072: 3072, KeyType.RSA_4096: 4096}
        key_size = sizes[config.key_type]
        private = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=self.backend
        )
        pub = private.public_key()
        priv_str = None
        if config.include_private:
            priv_str = private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_str = pub_bytes.decode()
        fingerprint = hashlib.sha256(pub_bytes).hexdigest()
        return GeneratedKey(
            key_type=config.key_type,
            private_key=priv_str,
            public_key=pub_str,
            metadata={"algorithm": "RSA", "key_size_bits": key_size},
            fingerprint=fingerprint,
            key_id=f"rsa_{key_size}_{int(time.time())}",
        )

    def _generate_ecc_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Cryptography library missing")
        mapping = {
            KeyType.ECC_SECP256R1: ec.SECP256R1(),
            KeyType.ECC_SECP384R1: ec.SECP384R1(),
            KeyType.ECC_SECP521R1: ec.SECP521R1(),
            KeyType.ECC_SECP256K1: ec.SECP256K1(),
        }
        curve = mapping[config.key_type]
        private = ec.generate_private_key(curve, self.backend)
        pub = private.public_key()
        priv_str = None
        if config.include_private:
            priv_str = private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_str = pub_bytes.decode()
        fingerprint = hashlib.sha256(pub_bytes).hexdigest()
        return GeneratedKey(
            key_type=config.key_type,
            private_key=priv_str,
            public_key=pub_str,
            metadata={"algorithm": "ECC", "curve": curve.name},
            fingerprint=fingerprint,
            key_id=f"ecc_{int(time.time())}",
        )


@dataclass
class AetheriumKeyPair:
    private_key: bytes
    public_key: bytes
    key_id: str
    created_at: datetime
    metadata: Dict[str, Any]


@dataclass
class AetheriumArtefact:
    ciphertext: bytes
    state_final: bytes
    signature: bytes
    proof: bytes
    checksum: bytes
    epsilon: bytes
    created_at: datetime


@dataclass
class SecurityConfig:
    enable_pqc: bool = True
    enable_zk_snarks: bool = True
    enable_fragmentation: bool = False
    enable_ipfs: bool = False
    quantum_noise_level: int = 5
    side_channel_protection: bool = True


class QuantumNoiseGenerator:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.noise_sources = [
            self._thermal_noise,
            self._em_noise,
            self._timing_noise,
            self._radioactive_decay_sim,
        ]

    def _thermal_noise(self) -> bytes:
        return secrets.token_bytes(32)

    def _em_noise(self) -> bytes:
        return secrets.token_bytes(24)

    def _timing_noise(self) -> bytes:
        timing_var = time.time_ns() % 1000000
        return struct.pack("<Q", timing_var)

    def _radioactive_decay_sim(self) -> bytes:
        decay_prob = secrets.randbits(8)
        return bytes([decay_prob])

    def generate_noise(self) -> bytes:
        noise = b""
        for source in self.noise_sources:
            noise += source()
        return hashlib.sha256(noise).digest()


class AetheriumUniverse:
    def __init__(self, public_key: bytes, noise_generator: QuantumNoiseGenerator):
        self.public_key = public_key
        self.noise_generator = noise_generator
        self.rounds = 64

    def evolve(self, epsilon: bytes) -> bytes:
        current_state = hashlib.sha3_512(epsilon + self.public_key + b"init").digest()
        for round_num in range(self.rounds):
            r_bytes = round_num.to_bytes(4, "big")
            noise = hashlib.sha3_512(epsilon + self.public_key + r_bytes + b"noise").digest()
            current_state = hashlib.sha3_512(
                current_state + epsilon + noise + self.public_key + r_bytes
            ).digest()
            current_state = bytes([
                b ^ (noise[i % len(noise)] if i % 2 == 0 else 0)
                for i, b in enumerate(current_state)
            ])
        return current_state

    def invert(self, private_key: bytes, target_state: bytes, epsilon: bytes) -> bool:
        computed = self.evolve(epsilon)
        if CRYPTO_AVAILABLE and _ct is not None:
            return _ct.bytes_eq(computed, target_state)
        return hmac.compare_digest(computed, target_state)


class AetheriumUltraKEM:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.noise_generator = QuantumNoiseGenerator(config)

    def generate_keypair(self) -> AetheriumKeyPair:
        private_key = secrets.token_bytes(64)
        public_key = hashlib.sha3_512(private_key).digest()
        key_id = f"aetherium_{int(time.time())}_{secrets.token_hex(8)}"
        return AetheriumKeyPair(
            private_key=private_key,
            public_key=public_key,
            key_id=key_id,
            created_at=datetime.now(),
            metadata={"algorithm": "AetheriumUltra", "key_size_bits": 512},
        )

    def encapsulate(
        self, recipient_public_key: bytes, sender_keypair: AetheriumKeyPair
    ) -> Tuple[AetheriumArtefact, bytes]:
        epsilon = secrets.token_bytes(64)
        universe = AetheriumUniverse(recipient_public_key, self.noise_generator)
        state_final = universe.evolve(epsilon)
        kyber_seed = secrets.token_bytes(64)
        kyber_ct = hashlib.sha3_512(recipient_public_key + kyber_seed + b"ct").digest() + kyber_seed
        kyber_ss = hashlib.sha3_512(recipient_public_key + kyber_seed + b"ss").digest()
        if CRYPTO_AVAILABLE and HKDF is not None:
            sort_vector = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=None,
                info=b"Aetherium-sort-vector",
                backend=default_backend(),
            ).derive(state_final + epsilon)
        else:
            sort_vector = hmac.new(
                state_final, epsilon + b"Aetherium-sort-vector", hashlib.sha3_512
            ).digest()
        session_key = hashlib.sha3_512(kyber_ss + sort_vector).digest()
        otp_mask = hashlib.shake_256(epsilon).digest(64)
        final_session = bytes(a ^ b for a, b in zip(session_key, otp_mask))
        signature = secrets.token_bytes(2048)
        proof = secrets.token_bytes(256)
        checksum = hashlib.sha3_512(kyber_ct + state_final + signature + proof).digest()[:32]
        artefact = AetheriumArtefact(
            ciphertext=kyber_ct,
            state_final=state_final,
            signature=signature,
            proof=proof,
            checksum=checksum,
            epsilon=epsilon,
            created_at=datetime.now(timezone.utc),
        )
        return artefact, final_session

    def decapsulate(self, private_keypair: AetheriumKeyPair, artefact: AetheriumArtefact) -> bytes:
        comp = hashlib.sha3_512(
            artefact.ciphertext + artefact.state_final + artefact.signature + artefact.proof
        ).digest()[:32]
        if CRYPTO_AVAILABLE and _ct is not None:
            checksum_ok = _ct.bytes_eq(comp, artefact.checksum)
        else:
            checksum_ok = hmac.compare_digest(comp, artefact.checksum)
        if not checksum_ok:
            raise ValueError("Checksum invalide")
        universe = AetheriumUniverse(private_keypair.public_key, self.noise_generator)
        if not universe.invert(private_keypair.private_key, artefact.state_final, artefact.epsilon):
            raise ValueError("Automaton state mismatch — clé incorrecte ou artefact altéré")
        if CRYPTO_AVAILABLE and HKDF is not None:
            sort_vector = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=None,
                info=b"Aetherium-sort-vector",
                backend=default_backend(),
            ).derive(artefact.state_final + artefact.epsilon)
        else:
            sort_vector = hmac.new(
                artefact.state_final, artefact.epsilon + b"Aetherium-sort-vector", hashlib.sha3_512
            ).digest()
        if len(artefact.ciphertext) >= 128:
            kyber_seed = artefact.ciphertext[64:128]
        else:
            kyber_seed = artefact.ciphertext
        kyber_ss = hashlib.sha3_512(private_keypair.public_key + kyber_seed + b"ss").digest()
        session_key = hashlib.sha3_512(kyber_ss + sort_vector).digest()
        otp_mask = hashlib.shake_256(artefact.epsilon).digest(64)
        final_session = bytes(a ^ b for a, b in zip(session_key, otp_mask))
        return final_session


class PostQuantumAlgorithm(Enum):
    KYBER_512 = "kyber512"
    KYBER_768 = "kyber768"
    KYBER_1024 = "kyber1024"
    DILITHIUM_2 = "dilithium2"
    DILITHIUM_3 = "dilithium3"


class SecurityLevel(Enum):
    LEVEL_1 = 128
    LEVEL_3 = 192
    LEVEL_5 = 256


@dataclass
class PQCKeyPair:
    algorithm: PostQuantumAlgorithm
    security_level: SecurityLevel
    public_key: bytes
    private_key: bytes
    ciphertext: Optional[bytes] = None
    shared_secret: Optional[bytes] = None
    signature: Optional[bytes] = None
    metadata: Optional[Dict[str, Any]] = None
    generation_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AetheriumCryptographicSuite:
    def __init__(self):
        self.security_level = SecurityLevel.LEVEL_5

    def generate_pqc_keypair(
        self,
        algorithm: PostQuantumAlgorithm,
        security_level: SecurityLevel = SecurityLevel.LEVEL_5,
    ) -> PQCKeyPair:
        priv = secrets.token_bytes(64)
        pub = hashlib.sha256(priv).digest()
        return PQCKeyPair(
            algorithm=algorithm,
            security_level=security_level,
            public_key=pub,
            private_key=priv,
        )

    def sign_message(self, keypair: PQCKeyPair, message: bytes) -> bytes:
        return hashlib.sha256(message).digest()

    def verify_signature(self, keypair: PQCKeyPair, message: bytes, signature: bytes) -> bool:
        return hashlib.sha256(message).digest() == signature


def run_suite_demo(verbose: bool = False) -> None:
    banner("AETHERIUM SUITE — Générateur, KEM Ultra, PQC")

    separator("1. GÉNÉRATEUR DE CLÉS UNIVERSEL")
    kg = CryptographicKeyGenerator()
    if not BIP39_AVAILABLE:
        info("Note BIP39", "bibliothèque absente — mnémoniques indisponibles")

    with timed_phase("génération AES-256", verbose):
        aes_cfg = KeyGenerationConfig(key_type=KeyType.AES_256, output_format=OutputFormat.HEX)
        aes_key = kg.generate_key(aes_cfg)

    info("Algorithme", "AES-256")
    info("Empreinte", aes_key.fingerprint or "—")
    info("Référence", aes_key.key_id or "—")
    if aes_key.private_key:
        fmt_bytes("Clé (aperçu)", bytes.fromhex(aes_key.private_key), verbose=verbose)
    if aes_key.metadata:
        info("Métadonnées", str(aes_key.metadata))

    separator("2. AETHERIUM ULTRA KEM (Architecture Hybride)")
    info("État", "512 bits, 64 tours chaotiques, HKDF-SHA3-512")
    kem = AetheriumUltraKEM(SecurityConfig())

    with timed_phase("génération paires Alice/Bob", verbose):
        sender = kem.generate_keypair()
        recipient = kem.generate_keypair()

    info("Alice PK", sender.public_key.hex()[:48] + "...")
    info("Bob   PK", recipient.public_key.hex()[:48] + "...")
    if verbose:
        fmt_bytes("Alice PK (complet)", sender.public_key, verbose=True)
        fmt_bytes("Bob   PK (complet)", recipient.public_key, verbose=True)

    with timed_phase("encapsulation Alice → Bob", verbose):
        artefact, session_alice = kem.encapsulate(recipient.public_key, sender)

    fmt_bytes("ε (graine)", artefact.epsilon, verbose=verbose)
    fmt_bytes("S_final", artefact.state_final, verbose=verbose)
    fmt_bytes("C_kyber", artefact.ciphertext, verbose=verbose)
    fmt_bytes("Σ (signature)", artefact.signature, verbose=verbose)
    fmt_bytes("C (checksum)", artefact.checksum, verbose=verbose)
    fmt_bytes("K_session Alice", session_alice, secret=True)

    if verbose:
        total = (
            len(artefact.ciphertext)
            + len(artefact.state_final)
            + len(artefact.signature)
            + len(artefact.proof)
            + len(artefact.checksum)
            + len(artefact.epsilon)
        )
        info("Taille artefact", f"{total} octets (tous champs publics)")

    with timed_phase("décapsulation Bob", verbose):
        try:
            session_bob = kem.decapsulate(recipient, artefact)
            sessions_equal = hmac.compare_digest(session_alice, session_bob)
            fmt_bytes("K_session Bob", session_bob, secret=True)
            summary_line(sessions_equal, "Concordance des clés de session")
        except Exception as exc:
            summary_line(False, f"Décapsulation échouée : {exc}")

    separator("3. POST-QUANTUM CRYPTOGRAPHIC SUITE (Simulation Kyber-1024)")
    suite = AetheriumCryptographicSuite()
    pqc = suite.generate_pqc_keypair(PostQuantumAlgorithm.KYBER_1024)
    info("Algorithme", pqc.algorithm.value.upper())
    info("Niveau sécu.", f"{pqc.security_level.value} bits")
    if verbose:
        fmt_bytes("PK PQC", pqc.public_key, verbose=True)

    message = b"Top Secret VIP Communication"
    sig = suite.sign_message(pqc, message)
    is_valid = suite.verify_signature(pqc, message, sig)
    info("Message", message.decode())
    fmt_bytes("Signature", sig, verbose=verbose)
    summary_line(is_valid, "Signature valide")

    print("\n" + "═" * 72)
    print("  FIN — Suite combinée")
    print("═" * 72 + "\n")
