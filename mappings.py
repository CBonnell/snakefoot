from pyasn1_alt_modules import rfc5480

import composite_asn1

OQS_ALG_TO_OID_MAPPINGS = {
    'Dilithium2': '1.3.6.1.4.1.2.267.7.4.4',
    'Dilithium3': '1.3.6.1.4.1.2.267.7.6.5',
    'Dilithium5': '1.3.6.1.4.1.2.267.7.8.7',
    'Falcon-512': '1.3.9999.3.6',
    'Falcon-1024': '1.3.9999.3.9',
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


DEPRECATED_OIDS = {
    '1.3.6.1.4.1.2.267.11.4.4',
    '1.3.6.1.4.1.2.267.11.6.5',
    '1.3.6.1.4.1.2.267.11.8.7',
    '1.3.9999.3.1',
    '1.3.9999.3.4',
    '1.3.9999.6.4.1',
    '1.3.9999.6.4.7',
    '1.3.9999.6.5.1',
    '1.3.9999.6.5.5',
    '1.3.9999.6.6.1',
    '1.3.9999.6.6.5',
}
