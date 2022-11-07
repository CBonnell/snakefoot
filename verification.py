import oqs
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280

import composite_asn1
import mappings


class Verifier:
    def __init__(self, spki: rfc5280.SubjectPublicKeyInfo):
        self._spki = spki

    @property
    def spki(self):
        return self._spki

    @staticmethod
    def _report_mismatch(subject_alg_oid, issuer_alg_oid):
        raise ValueError(f'Algorithm mismatch. Subject signature: {subject_alg_oid}.'
                         f'Issuer SPKI: {issuer_alg_oid}')

    def verify(self, message: bytes, signature: bytes, signature_algorithm: rfc5280.AlgorithmIdentifier):
        subject_sig_alg_oid = signature_algorithm['algorithm']
        issuer_spki_oid = self.spki['algorithm']['algorithm']

        oqs_alg_name = mappings.OID_TO_OQS_ALG_MAPPINGS.get(str(subject_sig_alg_oid))
        if oqs_alg_name is not None:
            if issuer_spki_oid != subject_sig_alg_oid:
                Verifier._report_mismatch(subject_sig_alg_oid, issuer_spki_oid)

            with oqs.Signature(oqs_alg_name) as verifier:
                return verifier.verify(message, signature, self.spki['subjectPublicKey'].asOctets())

        if subject_sig_alg_oid == composite_asn1.id_alg_composite:
            if issuer_spki_oid != composite_asn1.id_composite_key:
                Verifier._report_mismatch(subject_sig_alg_oid, issuer_spki_oid)
            spkis, _ = decode(self.spki['subjectPublicKey'].asOctets(), asn1Spec=composite_asn1.CompositePublicKey())
            signature_algs, _ = decode(
                signature_algorithm['parameters'].asOctets(), asn1Spec=composite_asn1.CompositeParams())
            signature_values, _ = decode(signature, asn1Spec=composite_asn1.CompositeSignatureValue())

            if not (len(spkis) == len(signature_algs) and len(signature_algs) == len(signature_values)):
                raise ValueError('Composite signature and SPKI element count mismatch')

            verifiers = [Verifier(s) for s in spkis]

            for v, spki, sig_alg, sig_value in zip(verifiers, spkis, signature_algs, signature_values):
                if not v.verify(message, sig_value, sig_alg):
                    return False

            return True

        raise ValueError(f'Unsupported signature algorithm: {subject_sig_alg_oid}')


def verify_subject_issuer_certificate(subject_cert, issuer_cert):
    subject_cert_sig_alg = subject_cert['tbsCertificate']['signature']
    subject_cert_tbs_octets = encode(subject_cert['tbsCertificate'])
    signature_octets = subject_cert['signature'].asOctets()

    verifier = Verifier(issuer_cert['tbsCertificate']['subjectPublicKeyInfo'])

    return verifier.verify(subject_cert_tbs_octets, signature_octets, subject_cert_sig_alg)


def verify_crl(crl, issuer_cert):
    crl_sig_alg = crl['tbsCertList']['signature']
    crl_tbs_octets = encode(crl['tbsCertList'])
    signature_octets = crl['signature'].asOctets()

    verifier = Verifier(issuer_cert['tbsCertificate']['subjectPublicKeyInfo'])

    return verifier.verify(crl_tbs_octets, signature_octets, crl_sig_alg)
