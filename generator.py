import argparse
import base64
import os
import shutil

from pyasn1.codec.der.encoder import encode

import chameleon
import key
import mappings
import signing
import tbs_builder


_ARTIFACT_DIRNAME = 'artifacts_certs_r3'


def _convert_to_pem(der, document_type='CERTIFICATE'):
    b64 = base64.encodebytes(der).decode().strip()

    return '\n'.join((f'-----BEGIN {document_type}-----', b64, f'-----END {document_type}-----'))


def persist_cert(cert, filename):
    der = encode(cert)
    pem = _convert_to_pem(der)

    with open(os.path.join(_ARTIFACT_DIRNAME, filename), 'w') as f:
        f.write(pem)


def build_root(key_pair, alt_key_pair=None, delta_cert=None):
    root_tbs = tbs_builder.build_root(key_pair.public_key, alt_key_pair.public_key if alt_key_pair else None)

    if delta_cert:
        root_tbs['extensions'].append(chameleon.build_delta_cert_descriptor(root_tbs, delta_cert))

    return signing.sign_tbscertificate(root_tbs, key_pair.private_key, alt_key_pair)


def build_ee(subject_key_pair, issuer_key_pair, alt_subject_key_pair=None, alt_issuer_key_pair=None, delta_cert=None):
    ee_tbs = tbs_builder.build_ee(subject_key_pair.public_key, issuer_key_pair.public_key,
                                  alt_subject_key_pair.public_key if alt_subject_key_pair else None)

    if delta_cert:
        ee_tbs['extensions'].append(chameleon.build_delta_cert_descriptor(ee_tbs, delta_cert))

    return signing.sign_tbscertificate(ee_tbs, issuer_key_pair.private_key, alt_issuer_key_pair)


parser = argparse.ArgumentParser()
parser.add_argument('output_dir', nargs='?', default='.')

args = parser.parse_args()

os.chdir(args.output_dir)

shutil.rmtree(_ARTIFACT_DIRNAME, True)
os.mkdir(_ARTIFACT_DIRNAME)

root_key_set = [key.OqsPrivateKey.generate(alg_name)
                for alg_name, alg_oid in mappings.OQS_ALG_TO_OID_MAPPINGS.items()
                if not any((alg_name.startswith(ap) for ap in mappings.ENCRYPTION_ALG_PREFIXES))]

ee_key_set = [key.OqsPrivateKey.generate(alg_name)
              for alg_name, alg_oid in mappings.OQS_ALG_TO_OID_MAPPINGS.items()
              if any((alg_name.startswith(ap) for ap in mappings.ENCRYPTION_ALG_PREFIXES))]

for root_key in root_key_set:
    cert = build_root(root_key)

    persist_cert(cert, f'{root_key.public_key.key_algorithm["algorithm"]}_ta.pem')

for ee_key in ee_key_set:
    signer_key_alg_oid = mappings.ENCRYPTION_ALG_EE_SIGNERS[str(ee_key.public_key.key_algorithm['algorithm'])]

    root_key = next((r for r in root_key_set if str(r.public_key.key_algorithm['algorithm']) == signer_key_alg_oid))

    cert = build_ee(ee_key, root_key)

    persist_cert(cert, f'{ee_key.public_key.key_algorithm["algorithm"]}_ee.pem')
