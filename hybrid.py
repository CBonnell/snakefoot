import functools

from pyasn1.codec.der.decoder import decode
from pyasn1_alt_modules import rfc5280

import hybrid_asn1
import key


def get_tbs(document):
    if isinstance(document, rfc5280.Certificate):
        return document['tbsCertificate']
    elif isinstance(document, rfc5280.CertificateList):
        return document['tbsCertList']
    else:
        return None


def _get_extensions(document):
    if isinstance(document, rfc5280.Certificate) and 'extensions' in document['tbsCertificate']:
        return document['tbsCertificate']['extensions']
    elif isinstance(document, rfc5280.CertificateList) and 'crlExtensions' in document['tbsCertList']:
        return document['tbsCertList']['crlExtensions']
    else:
        return None


def _set_extensions(document, exts):
    if isinstance(document, rfc5280.Certificate):
        document['tbsCertificate']['extensions'].clear()
        document['tbsCertificate']['extensions'].extend(exts)

    elif isinstance(document, rfc5280.CertificateList):
        document['tbsCertList']['crlExtensions'].clear()
        document['tbsCertList']['crlExtensions'].extend(exts)
    else:
        raise ValueError('Unknown document type')


def extract_classical_decoded_key(issuer_cert):
    return key.decode_spki(issuer_cert['tbsCertificate']['subjectPublicKeyInfo'])


def pop_extension(extn_oid, document):
    exts = _get_extensions(document)

    if exts is None:
        return None

    found_idx = None

    for i, ext in enumerate(exts):
        if ext['extnID'] == extn_oid:
            found_idx = i

            break

    if found_idx is None:
        return None
    else:
        new_exts = list(exts)

        popped_ext = new_exts.pop(found_idx)

        _set_extensions(document, new_exts)

        return popped_ext


def extract_alt_extension(extn_oid, extn_value_cls, document):
    exts = _get_extensions(document)

    if exts is None:
        return None

    ext = next((e for e in exts if e['extnID'] == extn_oid), None)

    if ext is None:
        return None

    decoded, _ = decode(ext['extnValue'].asOctets(), asn1Spec=extn_value_cls())

    return decoded


extract_alt_spki = functools.partial(extract_alt_extension, hybrid_asn1.id_ce_subjectAltPublicKeyInfo,
                                      hybrid_asn1.SubjectAltPublicKeyInfo)

extract_alt_signature_value = functools.partial(extract_alt_extension, hybrid_asn1.id_ce_altSignatureValue,
                                                 hybrid_asn1.AltSignatureValue)

extract_alt_signature_algorithm = functools.partial(extract_alt_extension, hybrid_asn1.id_ce_altSignatureAlgorithm,
                                                     hybrid_asn1.AltSignatureAlgorithm)


def extract_alt_decoded_key(issuer_cert):
    spki = extract_alt_spki(issuer_cert)

    if spki is None:
        return None

    return key.decode_spki(spki)
