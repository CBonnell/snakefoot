from pyasn1_alt_modules import rfc5480

OQS_ALG_TO_OID_MAPPINGS = {
    'Dilithium2': '1.3.6.1.4.1.2.267.12.4.4',
    'Dilithium3': '1.3.6.1.4.1.2.267.12.6.5',
    'Dilithium5': '1.3.6.1.4.1.2.267.12.8.7',
    'Falcon-512': '1.3.9999.3.6',
    'Falcon-1024': '1.3.9999.3.9',
    'SPHINCS+-SHA2-128s-simple': '1.3.9999.6.4.16',
    'SPHINCS+-SHAKE-128s-simple': '1.3.9999.6.7.16',
    'SPHINCS+-SHA2-128f-simple': '1.3.9999.6.4.13',
    'SPHINCS+-SHAKE-128f-simple': '1.3.9999.6.7.13',
    'SPHINCS+-SHA2-192s-simple': '1.3.9999.6.5.12',
    'SPHINCS+-SHAKE-192s-simple': '1.3.9999.6.8.12',
    'SPHINCS+-SHA2-192f-simple': '1.3.9999.6.5.10',
    'SPHINCS+-SHAKE-192f-simple': '1.3.9999.6.8.10',
    'SPHINCS+-SHA2-256s-simple': '1.3.9999.6.6.12',
    'SPHINCS+-SHAKE-256s-simple': '1.3.9999.6.9.12',
    'SPHINCS+-SHA2-256f-simple': '1.3.9999.6.6.10',
    'SPHINCS+-SHAKE-256f-simple': '1.3.9999.6.9.10',
    'Kyber512': '1.3.6.1.4.1.22554.5.6.1',
    'Kyber768': '1.3.6.1.4.1.22554.5.6.2',
    'Kyber1024': '1.3.6.1.4.1.22554.5.6.3',
}


ENCRYPTION_ALG_EE_SIGNERS = {
    OQS_ALG_TO_OID_MAPPINGS['Kyber512']: OQS_ALG_TO_OID_MAPPINGS['Dilithium2'],
    OQS_ALG_TO_OID_MAPPINGS['Kyber768']: OQS_ALG_TO_OID_MAPPINGS['Dilithium3'],
    OQS_ALG_TO_OID_MAPPINGS['Kyber1024']: OQS_ALG_TO_OID_MAPPINGS['Dilithium5'],
}


ENCRYPTION_ALG_PREFIXES = ['Kyber']


OID_TO_OQS_ALG_MAPPINGS = {
    v: k for k, v in OQS_ALG_TO_OID_MAPPINGS.items()
}


OID_TO_CLASSICAL_ALG_MAPPINGS = {
    str(rfc5480.ecdsa_with_SHA256): 'ECDSA-P256-with-SHA256',
    str(rfc5480.ecdsa_with_SHA384): 'ECDSA-P384-with-SHA384',
}


OID_TO_ALG_MAPPINGS = {
    **OID_TO_OQS_ALG_MAPPINGS,
    **OID_TO_CLASSICAL_ALG_MAPPINGS,
}


ALG_TO_OID_MAPPINGS = {
    v: k for k, v in OID_TO_ALG_MAPPINGS.items()
}
