import argparse
import csv
import enum
import os
import re
import sys

from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error
from pyasn1_alt_modules import rfc5280, pem, rfc2986

import key
import mappings
from verification import verify_subject_issuer_certificate, verify_crl, verify_csr


def print_to_err(message=''):
    print(message, file=sys.stderr)


def _read_pem_postels_law(path, document_cls):
    try:
        with open(path, 'r') as f:
            der = pem.readPemFromFile(f)
    except IOError as e:
        return None

    try:
        doc, _ = decode(der, asn1Spec=document_cls())
    except PyAsn1Error as e:
        print_to_err(f'Could not parse ASN.1 document "{path}": {e}')

        return None

    return doc


def _read_der_document(path, document_cls):
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


def _read_asn1_document(dir_path, artifact_type, filename, document_cls):
    if '.' not in filename:
        if document_cls == rfc5280.Certificate:
            der_file_ext = 'der'
        elif document_cls == rfc5280.CertificateList:
            der_file_ext = 'crl'
        else:
            der_file_ext = 'csr'

        der_path = os.path.join(dir_path, artifact_type, f'{filename}.{der_file_ext}')
        pem_path = os.path.join(dir_path, artifact_type, f'{filename}.pem')
    else:
        der_path = os.path.join(dir_path, artifact_type, filename)
        pem_path = None

    der_doc = _read_der_document(der_path, document_cls)

    if der_doc is not None:
        return der_doc

    if pem_path is not None:
        return _read_pem_postels_law(pem_path, document_cls)

    return None


def read_cert(dir_path, artifact_type, filename):
    return _read_asn1_document(dir_path, artifact_type, filename, rfc5280.Certificate)


def read_crl(dir_path, artifact_type, filename):
    return _read_asn1_document(dir_path, artifact_type, filename, rfc5280.CertificateList)


def read_csr(dir_path, artifact_type, filename):
    return _read_asn1_document(dir_path, artifact_type, filename, rfc2986.CertificationRequest)


def print_report(label, results_dirname):
    print_to_err('-' * 10 + ' ' + label.upper() + ' TESTS ' + '-' * 10)

    for result_dirname in results_dirname:
        print_to_err(' & '.join((mappings.OID_TO_ALG_MAPPINGS.get(r, r) for r in re.split(r'[^\d.]', result_dirname))))


def _execute_test(dir_path, signee, signer, signature_func, test):
    preamble = f'{dir_path}: '

    if not signee:
        print_to_err(preamble + f'{test} signee not specified')
        return '?'

    if not signer:
        print_to_err(preamble + f'{test} signer not specified')
        return '?'

    try:
        if signature_func == verify_csr:
            result = signature_func(signee)
        else:
            result = signature_func(signee, signer)

        if not result:
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
    ta_cert = read_cert(dir_path, 'ta', 'ta')
    ca_cert = read_cert(dir_path, 'ca', 'ca')
    ee_cert = read_cert(dir_path, 'ee', 'cert')

    ee_csr = read_csr(dir_path, 'ee', 'cert')

    ta_crl = read_crl(dir_path, 'crl', 'crl_ta')
    ca_crl = read_crl(dir_path, 'crl', 'crl_ca')


    row_dict = {
        'key_algorithm_oid': os.path.basename(dir_path),
        'ta': _execute_test(dir_path, ta_cert, ta_cert, verify_subject_issuer_certificate, 'Root'),
        'ca': _execute_test(dir_path, ca_cert, ta_cert, verify_subject_issuer_certificate, 'Intermediate'),
        'ee': _execute_test(dir_path, ee_cert, ca_cert, verify_subject_issuer_certificate, 'End-Entity'),
        'csr': _execute_test(dir_path, ee_csr, ee_csr, verify_csr, 'End-Entity CSR'),
        'crl_ta': _execute_test(dir_path, ta_crl, ta_cert, verify_crl, 'Root CRL'),
        'crl_ca': _execute_test(dir_path, ca_crl, ca_cert, verify_crl, 'Intermediate CRL'),
    }

    c.writerow(row_dict)

    return all(v == 'Y' for k, v in row_dict.items() if k in {'ta', 'ca', 'ee', 'crl_ta', 'crl_ca'})


passed_dir_tests = []
failed_dir_tests = []
not_executed_dir_tests = []

artifacts_path = os.path.join(args.dir_path, 'artifacts')

with open(f'{args.generator_name}_coreydigicert.csv', 'w') as f:
    c = csv.DictWriter(f, fieldnames=['key_algorithm_oid', 'ta', 'ca', 'ee', 'csr', 'crl_ta', 'crl_ca'])
    c.writeheader()

    for d in os.scandir(artifacts_path):
        if d.is_dir():
            try:
                if _execute_dir_test(c, os.path.join(artifacts_path, d.name)):
                    passed_dir_tests.append(d.name)
                else:
                    failed_dir_tests.append(d.name)
            except key.UnknownKeyTypeError as e:
                print_to_err(str(e))

                not_executed_dir_tests.append(d.name)



print_to_err()
print_report('failed', failed_dir_tests)
print_to_err()
print_report('passed', passed_dir_tests)
print_to_err()
print_report('skipped', not_executed_dir_tests)

exit(len(failed_dir_tests))
