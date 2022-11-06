import oqs
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280
import mappings


def get_verifier_from_certificate(cert: rfc5280.Certificate):
    sig_alg_oid = cert['tbsCertificate']['signature']['algorithm']

    sig_alg_name = mappings.OID_TO_ALG_MAPPINGS[str(sig_alg_oid)]

    return oqs.Signature(sig_alg_name)


def verify_subject_issuer_certificate(subject_cert, issuer_cert):
    subject_cert_sig_alg = subject_cert['tbsCertificate']['signature']['algorithm']
    issuer_cert_spki_alg = issuer_cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm']

    if subject_cert_sig_alg != issuer_cert_spki_alg:
        raise ValueError(f'Algorithm mismatch. Subject signature: {subject_cert_sig_alg}.'
                         f'Issuer SPKI: {issuer_cert_spki_alg}')

    subject_cert_tbs_octets = encode(subject_cert['tbsCertificate'])
    signature_octets = subject_cert['signature'].asOctets()
    issuer_public_key_octets = issuer_cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'].asOctets()

    with get_verifier_from_certificate(subject_cert) as verifier:
        return verifier.verify(subject_cert_tbs_octets, signature_octets, issuer_public_key_octets)


def verify_crl(crl, issuer_cert):
    crl_sig_alg = crl['tbsCertList']['signature']['algorithm']
    issuer_cert_spki_alg = issuer_cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm']

    if crl_sig_alg != issuer_cert_spki_alg:
        raise ValueError(f'Algorithm mismatch. Subject signature: {crl_sig_alg}.'
                         f'Issuer SPKI: {issuer_cert_spki_alg}')

    crl_tbs_octets = encode(crl['tbsCertList'])
    signature_octets = crl['signature'].asOctets()
    issuer_public_key_octets = issuer_cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'].asOctets()

    with get_verifier_from_certificate(issuer_cert) as verifier:
        return verifier.verify(crl_tbs_octets, signature_octets, issuer_public_key_octets)
