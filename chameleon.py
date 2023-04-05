from pyasn1.codec.cer.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280

import chameleon_asn1
import hybrid
import tbs_builder


def get_delta_cert_from_base_cert(cert: rfc5280.Certificate):
    # make a copy
    cert_der = encode(cert)

    chameleon_cert, _ = decode(cert_der, asn1Spec=cert)

    delta_desc_ext = hybrid.pop_extension(chameleon_asn1.id_ce_prototype_chameleon_delta_descriptor, chameleon_cert)

    delta_desc, _ = decode(delta_desc_ext['extnValue'], asn1Spec=chameleon_asn1.ChameleonDeltaDescriptor())

    chameleon_cert['tbsCertificate']['serialNumber'] = delta_desc['serialNumber']

    if 'signature' in delta_desc:
        chameleon_cert['tbsCertificate']['signature']['algorithm'] = delta_desc['signature']['algorithm']
        chameleon_cert['tbsCertificate']['signature']['parameters'] = delta_desc['signature']['parameters']

        chameleon_cert['signatureAlgorithm']['algorithm'] = delta_desc['signature']['algorithm']
        chameleon_cert['signatureAlgorithm']['parameters'] = delta_desc['signature']['parameters']

    if 'issuer' in delta_desc:
        chameleon_cert['tbsCertificate']['issuer']['rdnSequence'] = delta_desc['issuer']['rdnSequence']

    if 'subject' in delta_desc:
        chameleon_cert['tbsCertificate']['subject']['rdnSequence'] = delta_desc['subject']['rdnSequence']

    if 'subjectPublicKeyInfo' in delta_desc:
        chameleon_cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm'] = delta_desc['subjectPublicKeyInfo']['algorithm']
        chameleon_cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'] = delta_desc['subjectPublicKeyInfo']['subjectPublicKey']

    if 'extensions' in delta_desc:
        for delta_ext in delta_desc['extensions']:
            ext_idx = hybrid.get_extension_idx_by_oid(chameleon_cert['tbsCertificate']['extensions'],
                                                      delta_ext['extnID'])

            if ext_idx is None:
                raise ValueError(f'Extension with OID "{delta_ext["extnID"]}" not found in certificate')

            chameleon_cert['tbsCertificate']['extensions'][ext_idx]['critical'] = delta_ext['critical']
            chameleon_cert['tbsCertificate']['extensions'][ext_idx]['extnValue'] = delta_ext['extnValue']

    chameleon_cert['signature'] = delta_desc['signatureValue']

    return chameleon_cert


def _get_extn_oids(exts):
    return {e['extnID'] for e in exts}


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

    if encode(base_cert_tbs['subject']) == encode(delta_cert['tbsCertificate']['subject']):
        subject = None
    else:
        subject = delta_cert['tbsCertificate']['subject']

    if encode(base_cert_tbs['subjectPublicKeyInfo']) == encode(delta_cert['tbsCertificate']['subjectPublicKeyInfo']):
        spki = None
    else:
        spki = delta_cert['tbsCertificate']['subjectPublicKeyInfo']

    exts = []

    for ext in base_cert_tbs['extensions']:
        delta_ext_idx = hybrid.get_extension_idx_by_oid(delta_cert['tbsCertificate']['extensions'], ext['extnID'])

        if delta_ext_idx is None:
            continue

        delta_ext = delta_cert['tbsCertificate']['extensions'][delta_ext_idx]

        if encode(ext) == encode(delta_ext):
            continue
        else:
            exts.append(delta_ext)

    return tbs_builder.build_chameleon_delta_descriptor(
        delta_cert['tbsCertificate']['serialNumber'],
        delta_cert['signature'],
        sig_alg,
        issuer,
        subject,
        spki,
        exts
    )
