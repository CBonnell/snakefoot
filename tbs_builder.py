import binascii
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280, rfc5480

from pyasn1.type import char, univ, useful

from typing import Tuple, Sequence

import chameleon_asn1
import composite_asn1
import hybrid_asn1
import key
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


def _build_name(public_key, label, alt_public_key=None):
    alg_str = str(public_key.key_algorithm['algorithm'])

    alg_name = mappings.OID_TO_ALG_MAPPINGS.get(alg_str, alg_str)

    name = alg_name

    if alt_public_key:
        name += ' Hybrid Catalyst'

    name += f' {label}'

    return build_rdn_sequence([(rfc5280.id_at_stateOrProvinceName, name)])


def build_root_name(public_key, alt_public_key=None):
    return _build_name(public_key, 'Root', alt_public_key)


def build_intermediate_name(public_key, alt_public_key=None):
    return _build_name(public_key, 'Intermediate', alt_public_key)


def build_end_entity_name(public_key, alt_public_key=None):
    return _build_name(public_key, 'End-Entity', alt_public_key)


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


def build_alt_sig_alg(alg_id):
    return build_extension(hybrid_asn1.id_ce_altSignatureAlgorithm, alg_id)


def build_alt_spki(spki):
    return build_extension(hybrid_asn1.id_ce_subjectAltPublicKeyInfo, spki)


def build_alt_sig_value(value):
    alt_sig_value = hybrid_asn1.AltSignatureValue(value=value)

    return build_extension(hybrid_asn1.id_ce_altSignatureValue, alt_sig_value)


def build_chameleon_delta_descriptor(serial_number, signature_value, sig_alg=None, issuer=None, validity=None,
                                     subject=None, spki=None, extensions=None):
    if extensions is None:
        extensions = []

    ext_value = chameleon_asn1.ChameleonDeltaDescriptor()
    ext_value['serialNumber'] = serial_number
    ext_value['signatureValue'] = signature_value

    if sig_alg is not None:
        ext_value['signature']['algorithm'] = sig_alg['algorithm']
        ext_value['signature']['parameters'] = sig_alg['parameters']
    if issuer is not None:
        ext_value['issuer']['rdnSequence'] = issuer['rdnSequence']
    if validity is not None:
        ext_value['validity']['notBefore'] = validity['notBefore']
        ext_value['validity']['notAfter'] = validity['notAfter']
    if subject is not None:
        ext_value['subject']['rdnSequence'] = subject['rdnSequence']

    ext_value['subjectPublicKeyInfo']['algorithm'] = spki['algorithm']
    ext_value['subjectPublicKeyInfo']['subjectPublicKey'] = spki['subjectPublicKey']

    if extensions is not None:
        ext_value['extensions'].extend(extensions)

    return build_extension(chameleon_asn1.id_ce_prototype_chameleon_delta_descriptor, ext_value)


def _build_validity(validity_duration: datetime.timedelta):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    rfc5280_validity_period = validity_duration - datetime.timedelta(seconds=1)

    not_before = useful.UTCTime(now.strftime('%y%m%d000000Z'))
    not_after = useful.UTCTime((now + rfc5280_validity_period).strftime('%y%m%d235959Z'))

    return not_before, not_after


def build_tbscertificate(
        subject_public_key: key.PublicKey,
        issuer_public_key: key.PublicKey,
        issuer_name, subject_name,
        duration_days,
        extensions,
        subject_alt_public_key: key.PublicKey,
):
    tbs_cert = rfc5280.TBSCertificate()
    tbs_cert['version'] = rfc5280.Version.namedValues['v3']
    tbs_cert['serialNumber'] = univ.Integer(x509.random_serial_number())

    tbs_cert['signature'] = issuer_public_key.signature_algorithm

    tbs_cert['issuer']['rdnSequence'] = issuer_name

    validity = rfc5280.Validity()
    not_before, not_after = _build_validity(datetime.timedelta(days=duration_days))
    validity['notBefore']['utcTime'] = not_before
    validity['notAfter']['utcTime'] = not_after

    tbs_cert['validity'] = validity

    tbs_cert['subject']['rdnSequence'] = subject_name

    tbs_cert['subjectPublicKeyInfo'] = subject_public_key.to_spki

    tbs_cert['extensions'].extend(extensions)

    if subject_alt_public_key is not None:
        alt_spki_ext = build_alt_spki(subject_alt_public_key.to_spki)

        tbs_cert['extensions'].append(alt_spki_ext)

    return tbs_cert


def build_root(public_key, alt_public_key=None):
    name = build_root_name(public_key, alt_public_key)

    return build_tbscertificate(
        public_key,
        public_key,
        name, name,
        360,
        [build_basic_constraints(True),
         build_keyusage('digitalSignature,cRLSign,keyCertSign'),
         build_authority_key_identifier(public_key.encoded),
         build_subject_key_identifer(public_key.encoded)],
        alt_public_key
    )


def build_ica(subject_public_key, issuer_public_key, subject_alt_public_key=None):
    issuer_name = build_root_name(issuer_public_key)
    subject_name = build_intermediate_name(subject_public_key, subject_alt_public_key)

    return build_tbscertificate(
        subject_public_key,
        issuer_public_key,
        issuer_name, subject_name,
        180,
        [build_basic_constraints(True),
         build_keyusage('digitalSignature,cRLSign,keyCertSign'),
         build_authority_key_identifier(issuer_public_key.encoded),
         build_subject_key_identifer(subject_public_key.encoded)],
        subject_alt_public_key
    )


def build_ee(subject_public_key, issuer_public_key, subject_alt_public_key=None):
    issuer_name = build_intermediate_name(issuer_public_key)
    subject_name = build_end_entity_name(subject_public_key, subject_alt_public_key)

    return build_tbscertificate(
        subject_public_key, issuer_public_key,
        issuer_name, subject_name,
        90,
        [build_basic_constraints(False),
         build_keyusage('digitalSignature'),
         build_authority_key_identifier(issuer_public_key.encoded),
         build_subject_key_identifer(subject_public_key.encoded)],
        subject_alt_public_key
    )


def build_crl(is_root, issuer_public_key, issuer_alt_public_key=None):
    issuer_name = build_root_name(issuer_public_key, issuer_alt_public_key) if is_root else build_intermediate_name(
        issuer_public_key, issuer_alt_public_key)

    tbs_crl = rfc5280.TBSCertList()
    tbs_crl['version'] = rfc5280.Version.namedValues['v2']

    tbs_crl['signature'] = issuer_public_key.signature_algorithm

    tbs_crl['issuer']['rdnSequence'] = issuer_name
    this_update, next_update = _build_validity(datetime.timedelta(days=7))
    tbs_crl['thisUpdate']['utcTime'] = this_update
    tbs_crl['nextUpdate']['utcTime'] = next_update

    tbs_crl['crlExtensions'].extend((
        build_extension(rfc5280.id_ce_cRLNumber, rfc5280.CRLNumber(1), False),
        build_authority_key_identifier(issuer_public_key.encoded),
    ))

    return tbs_crl
