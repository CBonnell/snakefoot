import binascii

from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280

from pyasn1.type import univ

import oqs


def create_key(sig_alg_name):
    signer = oqs.Signature(sig_alg_name)
    return signer, signer.generate_keypair()


def sign_tbscertificate(signer: oqs.Signature,
                        tbs_certificate: rfc5280.TBSCertificate) -> rfc5280.Certificate:
    cert = rfc5280.Certificate()
    cert['tbsCertificate'] = tbs_certificate
    cert['signatureAlgorithm'] = tbs_certificate['signature']

    signature = signer.sign(encode(tbs_certificate))

    cert['signature'] = univ.BitString(hexValue=binascii.b2a_hex(signature))

    return cert


def sign_tbscertlist(signer: oqs.Signature,
                     tbs_certlist: rfc5280.TBSCertList) -> rfc5280.CertificateList:
    crl = rfc5280.CertificateList()
    crl['tbsCertList'] = tbs_certlist
    crl['signatureAlgorithm'] = tbs_certlist['signature']

    signature = signer.sign(encode(tbs_certlist))

    crl['signature'] = univ.BitString(hexValue=binascii.b2a_hex(signature))

    return crl
