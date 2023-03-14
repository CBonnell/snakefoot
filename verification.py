import functools

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280

import hybrid_asn1
import key
import hybrid


def _verify_alt_signature(doc_asn1, issuer_cert):
    alt_public_key_spki = hybrid.extract_alt_spki(issuer_cert)

    if alt_public_key_spki is None:
        return None

    alt_public_key = key.decode_spki(alt_public_key_spki)

    alt_signature_alg = hybrid.extract_alt_signature_algorithm(doc_asn1)

    if alt_signature_alg is None:
        return None

    der = encode(doc_asn1)
    doc_copy, _ = decode(der, asn1Spec=doc_asn1)

    alt_signature_value_ext = hybrid.pop_extension(hybrid_asn1.id_ce_altSignatureValue, doc_copy)

    if alt_signature_value_ext is None:
        raise ValueError('Certificate has alternate signature algorithm extension but no alternate signature value')

    alt_signature_value, _ = decode(alt_signature_value_ext['extnValue'], asn1Spec=hybrid_asn1.AltSignatureValue())

    tbs = hybrid.get_tbs(doc_copy)

    return alt_public_key.verify(encode(tbs), alt_signature_value.asOctets(), alt_signature_alg)


def verify_subject_issuer_certificate(subject_cert: rfc5280.Certificate, issuer_cert: rfc5280.Certificate) -> bool:
    subject_cert_sig_alg = subject_cert['tbsCertificate']['signature']
    subject_cert_tbs_octets = encode(subject_cert['tbsCertificate'])
    signature_octets = subject_cert['signature'].asOctets()

    issuer_classic_public_key = key.decode_spki(issuer_cert['tbsCertificate']['subjectPublicKeyInfo'])

    classic_verified = issuer_classic_public_key.verify(subject_cert_tbs_octets, signature_octets, subject_cert_sig_alg)

    if not classic_verified:
        return False

    alt_verified = _verify_alt_signature(subject_cert, issuer_cert)

    return alt_verified or alt_verified is None


def verify_crl(crl: rfc5280.CertificateList, issuer_cert: rfc5280.Certificate) -> bool:
    crl_sig_alg = crl['tbsCertList']['signature']
    crl_tbs_octets = encode(crl['tbsCertList'])
    signature_octets = crl['signature'].asOctets()

    issuer_classic_public_key = key.decode_spki(issuer_cert['tbsCertificate']['subjectPublicKeyInfo'])

    classic_verified = issuer_classic_public_key.verify(crl_tbs_octets, signature_octets, crl_sig_alg)

    if not classic_verified:
        return False

    alt_verified = _verify_alt_signature(crl, issuer_cert)

    return alt_verified or alt_verified is None
