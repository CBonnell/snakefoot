import argparse
import csv
import os
import re
import sys
import glob

from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error
from pyasn1_alt_modules import rfc5280, pem

import key
import mappings
from verification import verify_subject_issuer_certificate


def print_to_err(message=''):
    print(message, file=sys.stderr)


def _read_pem(path, document_cls):
    try:
        with open(path, 'r') as f:
            der = pem.readPemFromFile(f)
    except IOError as e:
        print_to_err(f'I/O error reading "{path}": {e}')
        return None

    try:
        doc, _ = decode(der, asn1Spec=document_cls())
    except PyAsn1Error as e:
        print_to_err(f'Could not parse ASN.1 document "{path}": {e}')

        return None

    return doc


def read_cert(filename):
    return _read_pem(filename, rfc5280.Certificate)


def _execute_test(signee, signer):
    alg = signee['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm']

    if not signee:
        print_to_err(f'{alg} signee not specified')
        return '?'

    if not signer:
        print_to_err(f'{alg} signer not specified')
        return '?'

    try:
        result = verify_subject_issuer_certificate(signee, signer)

        if not result:
            print_to_err(f'{alg} validation failed')
            return 'N'
    except ValueError as e:
        print_to_err(f'{alg} validation failed due to exception: "{e}"')
        return 'N'

    return 'Y'


parser = argparse.ArgumentParser()
parser.add_argument('generator_name')
parser.add_argument('dir_path', nargs='?', default='.')

args = parser.parse_args()

c = csv.DictWriter(sys.stdout, fieldnames=['key_algorithm_oid', 'test_result'])
c.writeheader()

for d in glob.glob(os.path.join(args.dir_path, '*.pem')):
    signee = read_cert(d)
    alg = str(signee['signatureAlgorithm']['algorithm'])

    if '_ee' in d:
        signer = read_cert(os.path.join(os.path.dirname(d), f'{alg}_ta.pem'))

        alg = str(signee['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm'])
    else:
        signer = signee

    try:
        ret = _execute_test(signee, signer)

        c.writerow({'key_algorithm_oid': alg, 'test_result': ret})
    except key.UnknownKeyTypeError as e:
        print_to_err(str(e))
