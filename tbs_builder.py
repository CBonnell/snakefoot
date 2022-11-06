import binascii

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280

from pyasn1.type import char, univ, useful

from typing import Tuple, Sequence

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


def _build_name(sig_alg_name, label):
    return build_rdn_sequence([(rfc5280.id_at_commonName, f'{sig_alg_name} {label}')])


def build_root_name(sig_alg_name):
    return _build_name(sig_alg_name, 'Root')


def build_intermediate_name(sig_alg_name):
    return _build_name(sig_alg_name, 'Intermediate')


def build_end_entity_name(sig_alg_name):
    return _build_name(sig_alg_name, 'End-Entity')


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


def build_tbscertificate(
        sig_alg_oid,
        issuer_name, subject_name,
        subject_key_oid, subject_key_value,
        extensions
):
    tbs_cert = rfc5280.TBSCertificate()
    tbs_cert['version'] = rfc5280.Version.namedValues['v3']
    tbs_cert['signature']['algorithm'] = sig_alg_oid
    tbs_cert['serialNumber'] = univ.Integer(x509.random_serial_number())

    tbs_cert['issuer']['rdnSequence'] = issuer_name

    validity = rfc5280.Validity()
    validity['notBefore']['utcTime'] = useful.UTCTime('221105000000Z')
    validity['notAfter']['utcTime'] = useful.UTCTime('321105000000Z')

    tbs_cert['validity'] = validity

    tbs_cert['subject']['rdnSequence'] = subject_name

    tbs_cert['subjectPublicKeyInfo']['algorithm']['algorithm'] = subject_key_oid
    tbs_cert['subjectPublicKeyInfo']['subjectPublicKey'] = univ.BitString(hexValue=binascii.b2a_hex(subject_key_value))

    tbs_cert['extensions'].extend(extensions)

    return tbs_cert


def build_root(sig_alg_name, subject_public_key_octets):
    name = build_root_name(sig_alg_name)

    key_oid_str = mappings.ALG_TO_OID_MAPPINGS[sig_alg_name]
    key_oid = univ.ObjectIdentifier(key_oid_str)

    return build_tbscertificate(
        key_oid,
        name, name,
        key_oid,
        subject_public_key_octets,
        [build_basic_constraints(True),
         build_keyusage('digitalSignature,cRLSign,keyCertSign'),
         build_authority_key_identifier(subject_public_key_octets),
         build_subject_key_identifer(subject_public_key_octets)]
    )


def build_ica(sig_alg_name, subject_public_key_octets, issuer_public_key_octets):
    issuer_name = build_root_name(sig_alg_name)
    subject_name = build_intermediate_name(sig_alg_name)

    key_oid_str = mappings.ALG_TO_OID_MAPPINGS[sig_alg_name]
    key_oid = univ.ObjectIdentifier(key_oid_str)

    return build_tbscertificate(
        key_oid,
        issuer_name, subject_name,
        key_oid,
        subject_public_key_octets,
        [build_basic_constraints(True),
         build_keyusage('digitalSignature,cRLSign,keyCertSign'),
         build_authority_key_identifier(issuer_public_key_octets),
         build_subject_key_identifer(subject_public_key_octets)]
    )


def build_ee(sig_alg_name, subject_public_key_octets, issuer_public_key_octets):
    issuer_name = build_intermediate_name(sig_alg_name)
    subject_name = build_end_entity_name(sig_alg_name)

    key_oid_str = mappings.ALG_TO_OID_MAPPINGS[sig_alg_name]
    key_oid = univ.ObjectIdentifier(key_oid_str)

    return build_tbscertificate(
        key_oid,
        issuer_name, subject_name,
        key_oid,
        subject_public_key_octets,
        [build_basic_constraints(False),
         build_keyusage('digitalSignature'),
         build_authority_key_identifier(issuer_public_key_octets),
         build_subject_key_identifer(subject_public_key_octets)]
    )


def build_crl(sig_alg_name, is_root, issuer_public_key_octets):
    issuer_name = build_root_name(sig_alg_name) if is_root else build_intermediate_name(sig_alg_name)

    key_oid_str = mappings.ALG_TO_OID_MAPPINGS[sig_alg_name]
    key_oid = univ.ObjectIdentifier(key_oid_str)

    tbs_crl = rfc5280.TBSCertList()
    tbs_crl['version'] = rfc5280.Version.namedValues['v2']
    tbs_crl['signature']['algorithm'] = key_oid
    tbs_crl['issuer']['rdnSequence'] = issuer_name
    tbs_crl['thisUpdate']['utcTime'] = useful.UTCTime('221106000000Z')
    tbs_crl['nextUpdate']['utcTime'] = useful.UTCTime('231106000000Z')

    tbs_crl['crlExtensions'].extend((
        build_extension(rfc5280.id_ce_cRLNumber, rfc5280.CRLNumber(1), False),
        build_authority_key_identifier(issuer_public_key_octets),
    ))

    return tbs_crl
