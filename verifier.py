import argparse
import os
import re

from pyasn1.error import PyAsn1Error
from pyasn1_alt_modules import rfc5280
from pyasn1.codec.der.decoder import decode

from verification import verify_subject_issuer_certificate, verify_crl
import mappings


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
        print(f'Could not parse ASN.1 document "{path}": {e}')

        return None

    return doc


def read_cert(dir_path, artifact_type, filename):
    return _read_asn1_document(dir_path, artifact_type, filename, rfc5280.Certificate)


def read_crl(dir_path, artifact_type, filename):
    return _read_asn1_document(dir_path, artifact_type, filename, rfc5280.CertificateList)


def print_report(label, results_dirname):
    print('-' * 10 + ' ' + label.upper() + ' TESTS ' + '-' * 10)

    for result_dirname in results_dirname:
        print(' & '.join((mappings.OID_TO_ALG_MAPPINGS.get(r, r) for r in re.split(r'[^\d.]', result_dirname))))


def _execute_test(dir_path, signee, signer, signature_func, test):
    preamble = f'{dir_path}: '

    if not signee:
        print(preamble + f'{test} signee not specified')
        return False

    if not signer:
        print(preamble + f'{test} signer not specified')
        return False

    try:
        if not signature_func(signee, signer):
            print(preamble + f'{test} failed')
            return False
    except ValueError as e:
        print(preamble + f'{test} failed due to exception: "{e}"')
        return False

    return True


parser = argparse.ArgumentParser()
parser.add_argument('dir_path', nargs='?', default='.')

args = parser.parse_args()


def _execute_dir_test(dir_path):
    ta_cert = read_cert(dir_path, 'ta', 'ta.der')
    ca_cert = read_cert(dir_path, 'ca', 'ca.der')
    ee_cert = read_cert(dir_path, 'ee', 'cert.der')

    ta_crl = read_crl(dir_path, 'crl', 'crl_ta.crl')
    ca_crl = read_crl(dir_path, 'crl', 'crl_ca.crl')

    is_good = (
            _execute_test(dir_path, ta_cert, ta_cert, verify_subject_issuer_certificate, 'Root') and
            _execute_test(dir_path, ca_cert, ta_cert, verify_subject_issuer_certificate, 'Intermediate') and
            _execute_test(dir_path, ee_cert, ca_cert, verify_subject_issuer_certificate, 'End-Entity') and
            _execute_test(dir_path, ta_crl, ta_cert, verify_crl, 'Root CRL') and
            _execute_test(dir_path, ca_crl, ca_cert, verify_crl, 'Intermediate CRL')
    )

    return is_good


passed_dir_tests = []
failed_dir_tests = []

artifacts_path = os.path.join(args.dir_path, 'artifacts')

for d in os.scandir(artifacts_path):
    if d.is_dir():
        if _execute_dir_test(os.path.join(artifacts_path, d.name)):
            passed_dir_tests.append(d.name)
        else:
            failed_dir_tests.append(d.name)


print()
print_report('failed', failed_dir_tests)
print()
print_report('passed', passed_dir_tests)

exit(len(failed_dir_tests))
