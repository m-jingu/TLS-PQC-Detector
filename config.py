#!/usr/bin/env python3
"""
Configuration file for TLS PQC Detector
Contains mappings for NamedGroups, CipherSuites, and Signature Algorithms
"""

# PQC NamedGroups (TLS 1.3) - Post-Quantum Cryptography
PQC_NAMED_GROUPS = {
    # NIST PQC Standardization Round 3 - Hybrid Key Exchange
    0xFE30: "x25519_kyber768_draft00",    # x25519 + Kyber-768 (draft)
    0xFE31: "x25519_kyber1024_draft00",   # x25519 + Kyber-1024 (draft)
    0xFE32: "x25519_mlkem768_draft00",    # x25519 + ML-KEM-768 (draft)
    0xFE33: "x448_kyber768_draft00",      # x448 + Kyber-768 (draft)
    0xFE34: "mlkem768",                   # ML-KEM-768 (draft)
    0xFE35: "mlkem1024",                  # ML-KEM-1024 (draft)
    
    # Additional PQC Key Exchange Groups (experimental/obsolete)
    0x6399: "x25519_kyber768_draft00_obsolete",  # X25519Kyber768Draft00 (OBSOLETE)
    
    # Additional PQC Key Exchange Groups (experimental)
    0xFE36: "kyber512",                   # Kyber-512 (experimental)
    0xFE37: "kyber768",                   # Kyber-768 (experimental)
    0xFE38: "kyber1024",                  # Kyber-1024 (experimental)
    
    # Experimental PQC NamedGroups (0x1100-0x11FF range)
    0x11EC: "x25519MLKEM768",             # x25519 + ML-KEM-768 (experimental)
}

# Classical NamedGroups (TLS 1.3) - Based on IANA TLS Supported Groups Registry
CLASSICAL_NAMED_GROUPS = {
    # Elliptic Curve Groups (RFC 4492, RFC 7027, RFC 7919)
    # Binary curves (deprecated)
    0x0001: "sect163k1",      # sect163k1 (deprecated, binary curve)
    0x0002: "sect163r1",      # sect163r1 (deprecated, binary curve)
    0x0003: "sect163r2",      # sect163r2 (deprecated, binary curve)
    0x0004: "sect193r1",      # sect193r1 (deprecated, binary curve)
    0x0005: "sect193r2",      # sect193r2 (deprecated, binary curve)
    0x0006: "sect233k1",      # sect233k1 (deprecated, binary curve)
    0x0007: "sect233r1",      # sect233r1 (deprecated, binary curve)
    0x0008: "sect239k1",      # sect239k1 (deprecated, binary curve)
    0x0009: "sect283k1",      # sect283k1 (deprecated, binary curve)
    0x000A: "sect283r1",      # sect283r1 (deprecated, binary curve)
    0x000B: "sect409k1",      # sect409k1 (deprecated, binary curve)
    0x000C: "sect409r1",      # sect409r1 (deprecated, binary curve)
    0x000D: "sect571k1",      # sect571k1 (deprecated, binary curve)
    0x000E: "sect571r1",      # sect571r1 (deprecated, binary curve)
    
    # Prime curves (deprecated)
    0x000F: "secp160k1",      # secp160k1 (deprecated, prime curve)
    0x0010: "secp160r1",      # secp160r1 (deprecated, prime curve)
    0x0011: "secp160r2",      # secp160r2 (deprecated, prime curve)
    0x0012: "secp192k1",      # secp192k1 (deprecated, prime curve)
    0x0013: "secp192r1",      # secp192r1 (deprecated, prime curve)
    0x0014: "secp224k1",      # secp224k1 (deprecated, prime curve)
    0x0015: "secp224r1",      # secp224r1 (deprecated, prime curve)
    0x0016: "secp256k1",      # secp256k1 (alternative ID, deprecated)
    0x0017: "secp256r1",      # secp256r1 (recommended)
    0x0018: "secp384r1",      # secp384r1 (recommended)
    0x0019: "secp521r1",      # secp521r1 (recommended)
    0x001A: "brainpoolP384r1", # brainpoolP384r1 (deprecated)
    0x001B: "brainpoolP512r1", # brainpoolP512r1 (deprecated)
    0x001C: "x25519",         # x25519 (deprecated, use 0x001D)
    0x001D: "x25519",         # x25519 (recommended)
    0x001E: "x448",           # x448 (recommended)
    
    # Finite Field Diffie-Hellman Groups (RFC 7919)
    0x001F: "ffdhe2048",     # ffdhe2048 (recommended)
    0x0020: "ffdhe3072",     # ffdhe3072 (recommended)
    0x0021: "ffdhe4096",     # ffdhe4096 (recommended)
    0x0022: "ffdhe6144",     # ffdhe6144 (recommended)
    0x0023: "ffdhe8192",     # ffdhe8192 (recommended)
    
    # Additional FFDHE Groups (detected in traffic)
    0x0100: "ffdhe2048_alt", # ffdhe2048 (alternative ID)
    0x0101: "ffdhe3072_alt", # ffdhe3072 (alternative ID)
    0x0102: "ffdhe4096_alt", # ffdhe4096 (alternative ID)
    0x0103: "ffdhe6144_alt", # ffdhe6144 (alternative ID)
    0x0104: "ffdhe8192_alt", # ffdhe8192 (alternative ID)
}

# GREASE values (should be filtered out)
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
}

# PQC Signature Algorithms - NIST PQC Standardization Round 3
PQC_SIGNATURE_ALGORITHMS = {
    # Dilithium (Primary Signature Algorithm)
    0x0807: "dilithium2",              # Dilithium-2 (recommended)
    0x0808: "dilithium3",              # Dilithium-3 (recommended)
    0x0809: "dilithium5",              # Dilithium-5 (recommended)
    
    # Falcon (Alternative Signature Algorithm)
    0x080A: "falcon512",               # Falcon-512 (recommended)
    0x080B: "falcon1024",              # Falcon-1024 (recommended)
    
    # SPHINCS+ (Backup Signature Algorithm)
    0x080C: "sphincs_sha256_128s",     # SPHINCS+-SHA256-128s (recommended)
    0x080D: "sphincs_sha256_128f",     # SPHINCS+-SHA256-128f (recommended)
    0x080E: "sphincs_sha256_192s",     # SPHINCS+-SHA256-192s (recommended)
    0x080F: "sphincs_sha256_192f",     # SPHINCS+-SHA256-192f (recommended)
    0x0810: "sphincs_sha256_256s",     # SPHINCS+-SHA256-256s (recommended)
    0x0811: "sphincs_sha256_256f",     # SPHINCS+-SHA256-256f (recommended)
    0x0812: "sphincs_shake256_128s",   # SPHINCS+-SHAKE256-128s (recommended)
    0x0813: "sphincs_shake256_128f",   # SPHINCS+-SHAKE256-128f (recommended)
    0x0814: "sphincs_shake256_192s",   # SPHINCS+-SHAKE256-192s (recommended)
    0x0815: "sphincs_shake256_192f",   # SPHINCS+-SHAKE256-192f (recommended)
    0x0816: "sphincs_shake256_256s",   # SPHINCS+-SHAKE256-256s (recommended)
    0x0817: "sphincs_shake256_256f",   # SPHINCS+-SHAKE256-256f (recommended)
}

# CipherSuite mappings (hex to name) - Common TLS 1.3 and 1.2 cipher suites
CIPHER_SUITES = {
    # TLS 1.3 cipher suites
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384", 
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    
    # TLS 1.2 cipher suites
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

# TLS version patterns for regex matching
TLS_VERSION_PATTERNS = {
    "TLS 1.2": r"0x0303",
    "TLS 1.3": r"0x0304", 
    "TLS 1.1": r"0x0302",
    "TLS 1.0": r"0x0301",
    "SSL 3.0": r"0x0300",
}

# Default processing parameters
DEFAULT_WORKERS = 8
DEFAULT_CHUNK_SIZE = 1000
DEFAULT_BUFFER_SIZE = 20000
DEFAULT_MODE = "both"
