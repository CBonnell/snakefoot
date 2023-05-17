from typing import Sequence, Optional

from pyasn1.codec.cer.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280, rfc2986, rfc2985

import chameleon_asn1
import hybrid
import tbs_builder


def _replace_extensions(dest_extensions, descriptor_extensions):
    for delta_ext in descriptor_extensions:
        ext_idx = hybrid.get_extension_idx_by_oid(dest_extensions, delta_ext['extnID'])

        if ext_idx is None:
            raise ValueError(f'Extension with OID "{delta_ext["extnID"]}" not found in certificate')

        dest_extensions[ext_idx]['critical'] = delta_ext['critical']
        dest_extensions[ext_idx]['extnValue'] = delta_ext['extnValue']


def pop_attribute(attr_type_oid, cri: rfc2986.CertificationRequestInfo) -> Optional[rfc2985.Attribute]:
    if 'attributes' not in cri:
        return None

    attr_idx = None
    for idx, attr in enumerate(cri['attributes']):
        if attr['type'] == attr_type_oid:
            attr_idx = idx
            break

    if attr_idx is None:
        return None
    else:
        new_attrs = list(cri['attributes'])

        popped_attr = new_attrs.pop(attr_idx)

        cri['attributes'].clear()
        cri['attributes'].extend(new_attrs)

        return popped_attr


def get_attribute_idx(attr_oid, attrs):
    for idx, attr in enumerate(attrs):
        if attr['type'] == attr_oid:
            return idx

    return None


def get_delta_cert_from_base_cert(cert: rfc5280.Certificate):
    # make a copy
    cert_der = encode(cert)

    chameleon_cert, _ = decode(cert_der, asn1Spec=cert)

    delta_desc_ext = hybrid.pop_extension(chameleon_asn1.id_ce_prototype_chameleon_delta_descriptor, chameleon_cert)

    delta_desc, _ = decode(delta_desc_ext['extnValue'], asn1Spec=chameleon_asn1.ChameleonDeltaDescriptor())

    chameleon_cert['tbsCertificate']['serialNumber'] = delta_desc['serialNumber']

    if delta_desc['signature'].isValue:
        chameleon_cert['tbsCertificate']['signature']['algorithm'] = delta_desc['signature']['algorithm']
        chameleon_cert['tbsCertificate']['signature']['parameters'] = delta_desc['signature']['parameters']

        chameleon_cert['signatureAlgorithm']['algorithm'] = delta_desc['signature']['algorithm']
        chameleon_cert['signatureAlgorithm']['parameters'] = delta_desc['signature']['parameters']

    if delta_desc['issuer'].isValue:
        chameleon_cert['tbsCertificate']['issuer']['rdnSequence'] = delta_desc['issuer']['rdnSequence']

    if delta_desc['validity'].isValue:
        chameleon_cert['tbsCertificate']['validity']['notBefore'] = delta_desc['validity']['notBefore']
        chameleon_cert['tbsCertificate']['validity']['notAfter'] = delta_desc['validity']['notAfter']

    if delta_desc['subject'].isValue:
        chameleon_cert['tbsCertificate']['subject']['rdnSequence'] = delta_desc['subject']['rdnSequence']

    chameleon_cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm'] = delta_desc['subjectPublicKeyInfo']['algorithm']
    chameleon_cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'] = delta_desc['subjectPublicKeyInfo']['subjectPublicKey']

    if delta_desc['extensions'].isValue:
        _replace_extensions(chameleon_cert['tbsCertificate']['extensions'], delta_desc['extensions'])

    chameleon_cert['signature'] = delta_desc['signatureValue']

    return chameleon_cert


def _get_extn_oids(exts):
    return {e['extnID'] for e in exts}


def build_delta_cert_descriptor_extensions(base_cert_exts: rfc5280.Extensions, delta_cert_exts: rfc5280.Extensions
                                           ) -> Optional[Sequence[rfc5280.Extension]]:
    exts = []

    for ext in base_cert_exts:
        delta_ext_idx = hybrid.get_extension_idx_by_oid(delta_cert_exts, ext['extnID'])

        if delta_ext_idx is None:
            continue

        delta_ext = delta_cert_exts[delta_ext_idx]

        if encode(ext) == encode(delta_ext):
            continue
        else:
            exts.append(delta_ext)

    return exts if any(exts) else None


def append_delta_cert_descriptor_request(base_cri: rfc2986.CertificationRequestInfo,
                                        base_sig_alg: rfc5280.AlgorithmIdentifier,
                                        delta_cri: rfc2986.CertificationRequestInfo,
                                        delta_sig_alg: rfc5280.AlgorithmIdentifier):
    if encode(base_cri['subject']) == encode(delta_cri['subject']):
        subject = None
    else:
        subject = delta_cri['subject']

    spki = delta_cri['subjectPKInfo']

    if base_cri['attributes'].isValue or delta_cri['attributes'].isValue:
        base_attr_idx = get_attribute_idx(rfc2985.pkcs_9_at_extensionRequest, base_cri['attributes'])
        delta_attr_idx = get_attribute_idx(rfc2985.pkcs_9_at_extensionRequest, delta_cri['attributes'])

        exts = build_delta_cert_descriptor_extensions(base_cri['attributes'][base_attr_idx]['values'][0],
                                                      delta_cri['attributes'][delta_attr_idx]['values'][0])
    else:
        exts = None

    if encode(base_sig_alg) == encode(delta_sig_alg):
        sig_alg = None
    else:
        sig_alg = delta_sig_alg

    attr = rfc2985.Attribute()
    attr['type'] = chameleon_asn1.id_at_delta_certificate_request

    attr_value = chameleon_asn1.ChameleonCertificateRequestDescriptor()

    if subject is not None:
        attr_value['subject']['rdnSequence'] = subject['rdnSequence']

    attr_value['subjectPKInfo'] = spki

    if exts is not None:
        attr_value['extensions'].extend(exts)

    if sig_alg is not None:
        attr_value['signatureAlgorithm']['algorithm'] = sig_alg['algorithm']
        attr_value['signatureAlgorithm']['parameters'] = sig_alg['parameters']

    attr['values'].append(attr_value)

    base_cri['attributes'].append(attr)

    return base_cri


def build_delta_cert_descriptor(base_cert_tbs: rfc5280.TBSCertificate, delta_cert: rfc5280.Certificate):
    if any(_get_extn_oids(delta_cert['tbsCertificate']['extensions']).difference(
            _get_extn_oids(base_cert_tbs['extensions']))):
        raise ValueError('Delta certificate contains extension(s) that are not present in Base certificate')

    if encode(base_cert_tbs['validity']) != encode(delta_cert['tbsCertificate']['validity']):
        raise ValueError('Base certificate and Delta certificate have different validity periods')

    if encode(base_cert_tbs['signature']) == encode(delta_cert['tbsCertificate']['signature']):
        sig_alg = None
    else:
        sig_alg = delta_cert['tbsCertificate']['signature']

    if encode(base_cert_tbs['issuer']) == encode(delta_cert['tbsCertificate']['issuer']):
        issuer = None
    else:
        issuer = delta_cert['tbsCertificate']['issuer']

    if encode(base_cert_tbs['validity']) == encode(delta_cert['tbsCertificate']['validity']):
        validity = None
    else:
        validity = delta_cert['tbsCertificate']['validity']

    if encode(base_cert_tbs['subject']) == encode(delta_cert['tbsCertificate']['subject']):
        subject = None
    else:
        subject = delta_cert['tbsCertificate']['subject']

    if encode(base_cert_tbs['subjectPublicKeyInfo']) == encode(delta_cert['tbsCertificate']['subjectPublicKeyInfo']):
        raise ValueError('SPKI in Base and Delta certificate cannot be the same')
    else:
        spki = delta_cert['tbsCertificate']['subjectPublicKeyInfo']


    exts = build_delta_cert_descriptor_extensions(base_cert_tbs['extensions'],
                                                  delta_cert['tbsCertificate']['extensions'])

    return tbs_builder.build_chameleon_delta_descriptor(
        delta_cert['tbsCertificate']['serialNumber'],
        delta_cert['signature'],
        sig_alg,
        issuer,
        validity,
        subject,
        spki,
        exts
    )
