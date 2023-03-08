import argparse
import csv
import os
import re
import sys

from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error
from pyasn1_alt_modules import rfc5280

import mappings
from verification import verify_subject_issuer_certificate, verify_crl


def print_to_err(message=''):
    print(message, file=sys.stderr)


def _read_asn1_document(dir_path, artifact_type, filename, document_cls):
    path = os.path.join(dir_path, artifact_type, filename)

    try:
        with open(path, 'rb') as f:
            der = f.read()
    except IOError as e:
        # print(f'Could not read file "{path}": {e}')
        return None

    try:
        doc, _ = decode(der, asn1Spec=document_cls())
    except PyAsn1Error as e:
        print_to_err(f'Could not parse ASN.1 document "{path}": {e}')

        return None

    return doc


def read_cert(dir_path, artifact_type, filename):
    return _read_asn1_document(dir_path, artifact_type, filename, rfc5280.Certificate)


def read_crl(dir_path, artifact_type, filename):
    return _read_asn1_document(dir_path, artifact_type, filename, rfc5280.CertificateList)


def print_report(label, results_dirname):
    print_to_err('-' * 10 + ' ' + label.upper() + ' TESTS ' + '-' * 10)

    for result_dirname in results_dirname:
        print_to_err(' & '.join((mappings.OID_TO_ALG_MAPPINGS.get(r, r) for r in re.split(r'[^\d.]', result_dirname))))


def _execute_test(dir_path, signee, signer, signature_func, test):
    preamble = f'{dir_path}: '

    if not signee:
        print_to_err(preamble + f'{test} signee not specified')
        return ''

    if not signer:
        print_to_err(preamble + f'{test} signer not specified')
        return ''

    try:
        if not signature_func(signee, signer):
            print_to_err(preamble + f'{test} failed')
            return 'N'
    except ValueError as e:
        print_to_err(preamble + f'{test} failed due to exception: "{e}"')
        return 'N'

    return 'Y'


parser = argparse.ArgumentParser()
parser.add_argument('generator_name')
parser.add_argument('dir_path', nargs='?', default='.')

args = parser.parse_args()


def _execute_dir_test(c, dir_path):
    ta_cert = read_cert(dir_path, 'ta', 'ta.der')
    ca_cert = read_cert(dir_path, 'ca', 'ca.der')
    ee_cert = read_cert(dir_path, 'ee', 'cert.der')

    ta_crl = read_crl(dir_path, 'crl', 'crl_ta.crl')
    ca_crl = read_crl(dir_path, 'crl', 'crl_ca.crl')

    row_dict = {
        'key_algorithm_oid': os.path.basename(dir_path),
        'ta': _execute_test(dir_path, ta_cert, ta_cert, verify_subject_issuer_certificate, 'Root'),
        'ca': _execute_test(dir_path, ca_cert, ta_cert, verify_subject_issuer_certificate, 'Intermediate'),
        'ee': _execute_test(dir_path, ee_cert, ca_cert, verify_subject_issuer_certificate, 'End-Entity'),
        'crl_ta': _execute_test(dir_path, ta_crl, ta_cert, verify_crl, 'Root CRL'),
        'crl_ca': _execute_test(dir_path, ca_crl, ca_cert, verify_crl, 'Intermediate CRL'),
    }

    c.writerow(row_dict)

    return all((v for v in row_dict.values()))


passed_dir_tests = []
failed_dir_tests = []

artifacts_path = os.path.join(args.dir_path, 'artifacts')

with open(f'{args.generator_name}_DigiCert.csv', 'w') as f:
    c = csv.DictWriter(f, fieldnames=['key_algorithm_oid', 'ta', 'ca', 'ee', 'crl_ta', 'crl_ca'])
    c.writeheader()

    for d in os.scandir(artifacts_path):
        if d.is_dir():
            if _execute_dir_test(c, os.path.join(artifacts_path, d.name)):
                passed_dir_tests.append(d.name)
            else:
                failed_dir_tests.append(d.name)


print_to_err()
print_report('failed', failed_dir_tests)
print_to_err()
print_report('passed', passed_dir_tests)

exit(len(failed_dir_tests))
