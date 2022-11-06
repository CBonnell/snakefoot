import oqs
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280
import mappings


def get_verifier_from_certificate(cert: rfc5280.Certificate):
    sig_alg_oid = cert['tbsCertificate']['signature']['algorithm']

    sig_alg_name = mappings.OID_TO_ALG_MAPPINGS[str(sig_alg_oid)]

    return oqs.Verifier(sig_alg_name)


def verify_certificate(issuer_public_key_octets, cert):
    tbs_cert_octets = encode(cert['tbsCertificate'])
    signature_octets = cert['signatureValue'].asOctets()

    verifier = get_verifier_from_certificate(cert)

    if not verifier.verify(tbs_cert_octets, signature_octets, issuer_public_key_octets):
        raise ValueError('Invalid signature')
