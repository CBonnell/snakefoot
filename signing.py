import binascii
from typing import Optional

from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280, rfc2986

from pyasn1.type import univ

import chameleon
import chameleon_asn1
import hybrid
import key
import tbs_builder


def _sign_with_alt_sig(key_pair: key.KeyPair, tbs, extensions):
    alt_sig_alg_ext = tbs_builder.build_alt_sig_alg(key_pair.public_key.signature_algorithm)

    extensions.append(alt_sig_alg_ext)

    pre_tbs = hybrid.get_pre_tbs_from_tbs(tbs)

    alt_signature = key_pair.private_key.sign(encode(pre_tbs))

    alt_sig_value_ext = tbs_builder.build_alt_sig_value(univ.BitString(hexValue=binascii.b2a_hex(alt_signature)))

    extensions.append(alt_sig_value_ext)

    return tbs


def sign_tbscertificate(tbs_certificate: rfc5280.TBSCertificate,
                        private_key: key.PrivateKey,
                        alt_key_pair: Optional[key.KeyPair] = None) -> rfc5280.Certificate:
    if alt_key_pair is not None:
        tbs_certificate = _sign_with_alt_sig(alt_key_pair, tbs_certificate, tbs_certificate['extensions'])

    cert = rfc5280.Certificate()
    cert['tbsCertificate'] = tbs_certificate
    cert['signatureAlgorithm'] = tbs_certificate['signature']

    signature = private_key.sign(encode(tbs_certificate))

    cert['signature'] = univ.BitString(hexValue=binascii.b2a_hex(signature))

    return cert


def sign_tbscertlist(tbs_certlist: rfc5280.TBSCertList,
                     private_key: key.PrivateKey,
                     alt_key_pair: Optional[key.KeyPair] = None) -> rfc5280.CertificateList:
    if alt_key_pair is not None:
        tbs_certlist = _sign_with_alt_sig(alt_key_pair, tbs_certlist, tbs_certlist['crlExtensions'])

    crl = rfc5280.CertificateList()
    crl['tbsCertList'] = tbs_certlist
    crl['signatureAlgorithm'] = tbs_certlist['signature']

    signature = private_key.sign(encode(tbs_certlist))

    crl['signature'] = univ.BitString(hexValue=binascii.b2a_hex(signature))

    return crl


def sign_csr(cri: rfc2986.CertificationRequestInfo, key_pair: key.KeyPair):
    csr = rfc2986.CertificationRequest()
    csr['certificationRequestInfo'] = cri
    csr['signatureAlgorithm'] = key_pair.public_key.signature_algorithm

    sig = key_pair.private_key.sign(encode(cri))
    csr['signature'] = univ.BitString(hexValue=sig.hex())

    return csr


def sign_chameleon_csr(base_cri: rfc2986.CertificationRequestInfo, base_key_pair: key.KeyPair,
                       delta_cri: rfc2986.CertificationRequestInfo, delta_key_pair: key.KeyPair):
    chameleon.append_delta_cert_descriptor_request(base_cri, base_key_pair.public_key.signature_algorithm,
                                                   delta_cri, delta_key_pair.public_key.signature_algorithm)

    csr_signed_delta_key = sign_csr(base_cri, delta_key_pair)

    delta_sig = csr_signed_delta_key['signature']

    attr = rfc5280.Attribute()
    attr['type'] = chameleon_asn1.id_at_delta_certificate_request_signature
    attr['values'].append(delta_sig)

    base_cri['attributes'].append(attr)

    return sign_csr(base_cri, base_key_pair)
