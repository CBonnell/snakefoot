import binascii

from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280, rfc5480

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

from pyasn1.type import univ

import oqs

import composite_asn1
import mappings
import tbs_builder


def _single_sign(signer, message):
    if isinstance(signer, ec.EllipticCurvePrivateKey):
        h = hashes.SHA256() if isinstance(signer.curve, ec.SECP256R1) else hashes.SHA384()
        return signer.sign(message, ec.ECDSA(h))
    else:
        return signer.sign(message)


def _sign(signers, message):
    if len(signers) == 1:
        return _single_sign(signers[0], message)
    else:
        sigs = [
            univ.BitString(hexValue=binascii.b2a_hex(_single_sign(s, message))) for s in signers
        ]

        sig_value = composite_asn1.CompositeSignatureValue()
        sig_value.extend(sigs)

        return encode(sig_value)


def create_key(sig_alg_oid):
    if sig_alg_oid in {str(rfc5480.ecdsa_with_SHA256), str(rfc5480.ecdsa_with_SHA384)}:
        curve = ec.SECP256R1() if sig_alg_oid == str(rfc5480.ecdsa_with_SHA256) else ec.SECP384R1()

        ec_private_key = ec.generate_private_key(curve)
        ec_public_key_octets = ec_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
        )

        return ec_private_key, ec_public_key_octets
    else:
        signer = oqs.Signature(mappings.OID_TO_OQS_ALG_MAPPINGS[sig_alg_oid])
        return signer, signer.generate_keypair()


def create_keys(sig_alg_oids):
    signers = []
    key_public_octets = []

    for sig_alg_oid in sig_alg_oids:
        signer, signer_public_octets = create_key(sig_alg_oid)

        signers.append(signer)
        key_public_octets.append(signer_public_octets)

    if len(sig_alg_oids) == 1:
        return signers, key_public_octets[0]
    else:
        return signers, tbs_builder.build_composite_key(sig_alg_oids, key_public_octets)


def sign_tbscertificate(signers,
                        tbs_certificate: rfc5280.TBSCertificate) -> rfc5280.Certificate:
    cert = rfc5280.Certificate()
    cert['tbsCertificate'] = tbs_certificate
    cert['signatureAlgorithm'] = tbs_certificate['signature']

    signature = _sign(signers, encode(tbs_certificate))

    cert['signature'] = univ.BitString(hexValue=binascii.b2a_hex(signature))

    return cert


def sign_tbscertlist(signers,
                     tbs_certlist: rfc5280.TBSCertList) -> rfc5280.CertificateList:
    crl = rfc5280.CertificateList()
    crl['tbsCertList'] = tbs_certlist
    crl['signatureAlgorithm'] = tbs_certlist['signature']

    signature = _sign(signers, encode(tbs_certlist))

    crl['signature'] = univ.BitString(hexValue=binascii.b2a_hex(signature))

    return crl
