from pyasn1.codec.der.encoder import encode

import key


def verify_subject_issuer_certificate(subject_cert, issuer_cert):
    subject_cert_sig_alg = subject_cert['tbsCertificate']['signature']
    subject_cert_tbs_octets = encode(subject_cert['tbsCertificate'])
    signature_octets = subject_cert['signature'].asOctets()

    issuer_public_key = key.decode_spki(issuer_cert['tbsCertificate']['subjectPublicKeyInfo'])

    return issuer_public_key.verify(subject_cert_tbs_octets, signature_octets, subject_cert_sig_alg)


def verify_crl(crl, issuer_cert):
    crl_sig_alg = crl['tbsCertList']['signature']
    crl_tbs_octets = encode(crl['tbsCertList'])
    signature_octets = crl['signature'].asOctets()

    issuer_public_key = key.decode_spki(issuer_cert['tbsCertificate']['subjectPublicKeyInfo'])

    return issuer_public_key.verify(crl_tbs_octets, signature_octets, crl_sig_alg)
