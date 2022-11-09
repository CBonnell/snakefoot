import binascii

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280, rfc5480

from pyasn1.type import char, univ, useful

from typing import Tuple, Sequence

import composite_asn1
import mappings


def build_rdn_sequence(rdns: Sequence[Tuple[univ.ObjectIdentifier, str]]):
    rdn_seq = rfc5280.RDNSequence()

    for oid, value in rdns:
        rdn = rfc5280.RelativeDistinguishedName()

        atv = rfc5280.AttributeTypeAndValue()
        atv['type'] = oid
        atv['value'] = char.UTF8String(value)

        rdn.append(atv)
        rdn_seq.append(rdn)

    return rdn_seq


def _build_name(sig_alg_oids, label):
    alg_name = ' & '.join(
        (
            mappings.OID_TO_ALG_MAPPINGS[s] for s in sig_alg_oids
        )
    )

    return build_rdn_sequence([(rfc5280.id_at_stateOrProvinceName, f'{alg_name} {label}')])


def build_root_name(sig_alg_oids):
    return _build_name(sig_alg_oids, 'Root')


def build_intermediate_name(sig_alg_oids):
    return _build_name(sig_alg_oids, 'Intermediate')


def build_end_entity_name(sig_alg_oids):
    return _build_name(sig_alg_oids, 'End-Entity')


def calculate_key_identifier(key_octets: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA1())
    h.update(key_octets)

    return h.finalize()


def build_extension(type_oid, pyasn1_value, critical=False):
    ext = rfc5280.Extension()
    ext['extnID'] = type_oid
    ext['critical'] = critical
    ext['extnValue'] = encode(pyasn1_value)

    return ext


def build_basic_constraints(is_ca):
    bc = rfc5280.BasicConstraints()

    bc['cA'] = is_ca

    return build_extension(rfc5280.id_ce_basicConstraints, bc, True)


def build_authority_key_identifier(key_octets: bytes):
    aki = rfc5280.AuthorityKeyIdentifier()
    aki['keyIdentifier'] = calculate_key_identifier(key_octets)

    return build_extension(rfc5280.id_ce_authorityKeyIdentifier, aki)


def build_subject_key_identifer(key_octets: bytes):
    ski = rfc5280.SubjectKeyIdentifier(value=calculate_key_identifier(key_octets))

    return build_extension(rfc5280.id_ce_subjectKeyIdentifier, ski)


def build_keyusage(value):
    ku = rfc5280.KeyUsage(value=value)

    return build_extension(rfc5280.id_ce_keyUsage, ku, True)


def build_composite_sig_alg_params(sig_alg_oids):
    params = composite_asn1.CompositeParams()

    for sig_alg_oid in sig_alg_oids:
        sig_alg_id = rfc5280.AlgorithmIdentifier()
        sig_alg_id['algorithm'] = univ.ObjectIdentifier(sig_alg_oid)

        params.append(sig_alg_id)

    return encode(params)


def build_composite_key(sig_alg_oids, public_keys_octets):
    composite_key = composite_asn1.CompositePublicKey()

    for sig_alg_oid, public_key_octets in zip(sig_alg_oids, public_keys_octets):
        spki = rfc5280.SubjectPublicKeyInfo()
        spki['algorithm'] = build_key_alg_id_from_sig_alg(sig_alg_oid)
        spki['subjectPublicKey'] = univ.BitString(hexValue=binascii.b2a_hex(public_key_octets))

        composite_key.append(spki)

    return encode(composite_key)


def build_key_alg_id_from_sig_alg(sig_alg_oid):
    alg_id = rfc5280.AlgorithmIdentifier()

    if sig_alg_oid in mappings.OID_TO_OQS_ALG_MAPPINGS:
        alg_id['algorithm'] = univ.ObjectIdentifier(sig_alg_oid)
    elif sig_alg_oid in {str(rfc5480.ecdsa_with_SHA256), str(rfc5480.ecdsa_with_SHA384)}:
        curve = rfc5480.secp256r1 if sig_alg_oid == str(rfc5480.ecdsa_with_SHA256) else rfc5480.secp384r1

        alg_id['algorithm'] = rfc5480.id_ecPublicKey
        alg_id['parameters'] = encode(curve)
    else:
        raise ValueError(f'Unknown signature algorithm: {sig_alg_oid}')

    return alg_id


def build_tbscertificate(
        sig_alg_oids,
        issuer_name, subject_name,
        subject_key_value,
        extensions
):
    tbs_cert = rfc5280.TBSCertificate()
    tbs_cert['version'] = rfc5280.Version.namedValues['v3']
    tbs_cert['serialNumber'] = univ.Integer(x509.random_serial_number())

    if len(sig_alg_oids) == 1:
        tbs_cert['signature']['algorithm'] = sig_alg_oids[0]
    else:
        tbs_cert['signature']['algorithm'] = composite_asn1.id_alg_composite
        tbs_cert['signature']['parameters'] = build_composite_sig_alg_params(sig_alg_oids)

    tbs_cert['issuer']['rdnSequence'] = issuer_name

    validity = rfc5280.Validity()
    validity['notBefore']['utcTime'] = useful.UTCTime('221105000000Z')
    validity['notAfter']['utcTime'] = useful.UTCTime('321105000000Z')

    tbs_cert['validity'] = validity

    tbs_cert['subject']['rdnSequence'] = subject_name

    if len(sig_alg_oids) == 1:
        tbs_cert['subjectPublicKeyInfo']['algorithm'] = build_key_alg_id_from_sig_alg(sig_alg_oids[0])
    else:
        tbs_cert['subjectPublicKeyInfo']['algorithm']['algorithm'] = composite_asn1.id_composite_key
    tbs_cert['subjectPublicKeyInfo']['subjectPublicKey'] = univ.BitString(hexValue=binascii.b2a_hex(subject_key_value))

    tbs_cert['extensions'].extend(extensions)

    return tbs_cert


def build_root(sig_alg_oids, subject_public_key_octets):
    name = build_root_name(sig_alg_oids)

    return build_tbscertificate(
        sig_alg_oids,
        name, name,
        subject_public_key_octets,
        [build_basic_constraints(True),
         build_keyusage('digitalSignature,cRLSign,keyCertSign'),
         build_authority_key_identifier(subject_public_key_octets),
         build_subject_key_identifer(subject_public_key_octets)]
    )


def build_ica(sig_alg_oids, subject_public_key_octets, issuer_public_key_octets):
    issuer_name = build_root_name(sig_alg_oids)
    subject_name = build_intermediate_name(sig_alg_oids)

    return build_tbscertificate(
        sig_alg_oids,
        issuer_name, subject_name,
        subject_public_key_octets,
        [build_basic_constraints(True),
         build_keyusage('digitalSignature,cRLSign,keyCertSign'),
         build_authority_key_identifier(issuer_public_key_octets),
         build_subject_key_identifer(subject_public_key_octets)]
    )


def build_ee(sig_alg_oids, subject_public_key_octets, issuer_public_key_octets):
    issuer_name = build_intermediate_name(sig_alg_oids)
    subject_name = build_end_entity_name(sig_alg_oids)

    return build_tbscertificate(
        sig_alg_oids,
        issuer_name, subject_name,
        subject_public_key_octets,
        [build_basic_constraints(False),
         build_keyusage('digitalSignature'),
         build_authority_key_identifier(issuer_public_key_octets),
         build_subject_key_identifer(subject_public_key_octets)]
    )


def build_crl(sig_alg_oids, is_root, issuer_public_key_octets):
    issuer_name = build_root_name(sig_alg_oids) if is_root else build_intermediate_name(sig_alg_oids)

    tbs_crl = rfc5280.TBSCertList()
    tbs_crl['version'] = rfc5280.Version.namedValues['v2']

    if len(sig_alg_oids) == 1:
        tbs_crl['signature']['algorithm'] = sig_alg_oids[0]
    else:
        tbs_crl['signature']['algorithm'] = composite_asn1.id_alg_composite
        tbs_crl['signature']['parameters'] = build_composite_sig_alg_params(sig_alg_oids)

    tbs_crl['issuer']['rdnSequence'] = issuer_name
    tbs_crl['thisUpdate']['utcTime'] = useful.UTCTime('221106000000Z')
    tbs_crl['nextUpdate']['utcTime'] = useful.UTCTime('231106000000Z')

    tbs_crl['crlExtensions'].extend((
        build_extension(rfc5280.id_ce_cRLNumber, rfc5280.CRLNumber(1), False),
        build_authority_key_identifier(issuer_public_key_octets),
    ))

    return tbs_crl
