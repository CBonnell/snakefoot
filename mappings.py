from pyasn1_alt_modules import rfc5480

import composite_asn1

OQS_ALG_TO_OID_MAPPINGS = {
    'Dilithium2': '1.3.6.1.4.1.2.267.7.4.4',
    'Dilithium3': '1.3.6.1.4.1.2.267.7.6.5',
    'Dilithium5': '1.3.6.1.4.1.2.267.7.8.7',
    'Dilithium2-AES': '1.3.6.1.4.1.2.267.11.4.4',
    'Dilithium3-AES': '1.3.6.1.4.1.2.267.11.6.5',
    'Dilithium5-AES': '1.3.6.1.4.1.2.267.11.8.7',
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
