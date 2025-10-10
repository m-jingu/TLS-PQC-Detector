#!/usr/bin/env python3
"""
Configuration file for TLS PQC Detector
Contains mappings for NamedGroups, CipherSuites, and Signature Algorithms
"""

# PQC NamedGroups (TLS 1.3)
PQC_NAMED_GROUPS = {
    0xFE30: "x25519_kyber768_draft00",
    0xFE31: "x25519_kyber1024_draft00", 
    0xFE32: "x25519_mlkem768_draft00",
    0xFE34: "mlkem768",
}

# Classical NamedGroups (TLS 1.3)
CLASSICAL_NAMED_GROUPS = {
    0x001D: "x25519",
    0x001E: "x448", 
    0x001F: "ffdhe2048",
    0x0020: "ffdhe3072",
    0x0021: "ffdhe4096",
    0x0022: "ffdhe6144",
    0x0023: "ffdhe8192",
}

# PQC Signature Algorithms
PQC_SIGNATURE_ALGORITHMS = {
    0x0807: "dilithium2",
    0x0808: "dilithium3", 
    0x0809: "dilithium5",
    0x080A: "falcon512",
    0x080B: "falcon1024",
    0x080C: "sphincs_sha256_128s",
    0x080D: "sphincs_sha256_128f",
    0x080E: "sphincs_sha256_192s",
    0x080F: "sphincs_sha256_192f",
    0x0810: "sphincs_sha256_256s",
    0x0811: "sphincs_sha256_256f",
    0x0812: "sphincs_shake256_128s",
    0x0813: "sphincs_shake256_128f",
    0x0814: "sphincs_shake256_192s",
    0x0815: "sphincs_shake256_192f",
    0x0816: "sphincs_shake256_256s",
    0x0817: "sphincs_shake256_256f",
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
