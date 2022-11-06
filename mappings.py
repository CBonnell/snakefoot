ALG_TO_OID_MAPPINGS = {
    'Dilithium2': '1.3.6.1.4.1.2.267.7.4.4',
    'Dilithium3': '1.3.6.1.4.1.2.267.7.4.5',
    'Dilithium5': '1.3.6.1.4.1.2.267.7.4.7',
    'Dilithium2-AES': '1.3.6.1.4.1.2.267.11.4.4',
    'Dilithium3-AES': '1.3.6.1.4.1.2.267.11.4.5',
    'Dilithium5-AES': '1.3.6.1.4.1.2.267.11.4.7',
    'Falcon-512': '1.3.9999.3.1',
    'Falcon-1024': '1.3.9999.3.4',
    'SPHINCS+-SHA256-128f-robust': '1.3.9999.6.4.1',
    'SPHINCS+-SHA256-128f-simple': '1.3.9999.6.4.4',
    'SPHINCS+-SHA256-128s-robust': '1.3.9999.6.4.7',
    'SPHINCS+-SHA256-128s-simple': '1.3.9999.6.4.10',
    'SPHINCS+-SHA256-192f-robust': '1.3.9999.6.5.1',
    'SPHINCS+-SHA256-192f-simple': '1.3.9999.6.5.3',
    'SPHINCS+-SHA256-192s-robust': '1.3.9999.6.5.5',
    'SPHINCS+-SHA256-192s-simple': '1.3.9999.6.5.7',
    'SPHINCS+-SHA256-256f-robust': '1.3.9999.6.6.1',
    'SPHINCS+-SHA256-256f-simple': '1.3.9999.6.6.3',
    'SPHINCS+-SHA256-256s-robust': '1.3.9999.6.6.5',
    'SPHINCS+-SHA256-256s-simple': '1.3.9999.6.6.7',
}


OID_TO_ALG_MAPPINGS = {
    v: k for k, v in ALG_TO_OID_MAPPINGS.items()
}
