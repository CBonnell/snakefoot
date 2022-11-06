import argparse
import base64
import os
import zipfile

import pyasn1.error
from pyasn1_alt_modules import rfc5280
from pyasn1.codec.der.decoder import decode

from verification import verify_subject_issuer_certificate, verify_crl
import mappings


def _read_asn1_document(z, sig_alg_oid, subdir, filename, document_cls):
    path = os.path.join(sig_alg_oid, subdir, filename)

    try:
        der = z.read(path)
    except KeyError:
        artifacts_path = os.path.join('artifacts', path)

        try:
            der = z.read(artifacts_path)
        except KeyError:
            return None

    doc, _ = decode(der, asn1Spec=document_cls())

    return doc


def read_cert(z, sig_alg_oid, subdir, filename):
    return _read_asn1_document(z, sig_alg_oid, subdir, filename, rfc5280.Certificate)


def read_crl(z, sig_alg_oid, subdir, filename):
    return _read_asn1_document(z, sig_alg_oid, subdir, filename, rfc5280.CertificateList)


def print_report(label, oids):
    print('-' * 10 + ' ' + label.upper() + ' ALGORITHMS ' + '-' * 10)
    for oid in oids:
        name = mappings.OID_TO_ALG_MAPPINGS[oid]

        print(f'{name} ({oid})')


def _execute_test(sig_alg_oid, signee, signer, signature_func, test):
    sig_alg_name = mappings.OID_TO_ALG_MAPPINGS[sig_alg_oid]

    preamble = f'{sig_alg_name} ({sig_alg_oid}): '

    if not signee:
        print(preamble + f'{test} signee not specified')
        return False

    if not signer:
        print(preamble + f'{test} signer not specified')
        return False

    if not signature_func(signee, signer):
        print(preamble + f'{test} failed')
        return False

    return True


parser = argparse.ArgumentParser()
parser.add_argument('file', type=argparse.FileType('rb'))

args = parser.parse_args()

good_oids = []
bad_oids = []

with zipfile.ZipFile(args.file) as z:
    for sig_alg_oid in mappings.OID_TO_ALG_MAPPINGS.keys():
        ta_cert = read_cert(z, sig_alg_oid, 'ta', 'ta.der')
        ca_cert = read_cert(z, sig_alg_oid, 'ca', 'ca.der')
        ee_cert = read_cert(z, sig_alg_oid, 'ee', 'cert.der')

        ta_crl = read_crl(z, sig_alg_oid, 'crl', 'crl_ta.crl')
        ca_crl = read_crl(z, sig_alg_oid, 'crl', 'crl_ca.crl')

        is_good = (
                    _execute_test(sig_alg_oid, ta_cert, ta_cert, verify_subject_issuer_certificate, 'Root') and
                    _execute_test(sig_alg_oid, ca_cert, ta_cert, verify_subject_issuer_certificate, 'Intermediate') and
                    _execute_test(sig_alg_oid, ee_cert, ca_cert, verify_subject_issuer_certificate, 'End-Entity') and
                    _execute_test(sig_alg_oid, ta_crl, ta_cert, verify_crl, 'Root CRL') and
                    _execute_test(sig_alg_oid, ca_crl, ca_cert, verify_crl, 'Intermediate CRL')
                   )

        if is_good:
            good_oids.append(sig_alg_oid)
        else:
            bad_oids.append(sig_alg_oid)

print()
print_report('bad', bad_oids)
print()
print_report('good', good_oids)

exit(len(bad_oids))
