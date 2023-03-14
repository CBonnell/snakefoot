import binascii
from typing import Optional

from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280

from pyasn1.type import univ

import key
import tbs_builder


def _sign_with_alt_sig(key_pair: key.KeyPair, tbs, extensions):
    alt_sig_alg_ext = tbs_builder.build_alt_sig_alg(key_pair.public_key.signature_algorithm)

    extensions.append(alt_sig_alg_ext)

    alt_signature = key_pair.private_key.sign(encode(tbs))

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
