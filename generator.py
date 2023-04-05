from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5480

import chameleon
import composite_asn1
import key
import mappings
import signing
import tbs_builder
import os
import shutil
import argparse


def persist_artifact(key_oid, subdir, filename, content):
    dir_path = os.path.join('artifacts', key_oid, subdir)
    os.makedirs(dir_path, exist_ok=True)

    path = os.path.join(dir_path, filename)

    with open(path, 'wb') as f:
        if not isinstance(content, bytes):
            content = encode(content)

        f.write(content)


def persist(key_oid,
            root_cert, root_crl,
            ica_cert, ica_crl,
            ee_cert):
    persist_artifact(key_oid, 'ta', 'ta.der', encode(root_cert))

    persist_artifact(key_oid, 'ca', 'ca.der', encode(ica_cert))

    persist_artifact(key_oid, 'ee', 'cert.der', encode(ee_cert))

    persist_artifact(key_oid, 'crl', 'crl_ta.crl', encode(root_crl))
    persist_artifact(key_oid, 'crl', 'crl_ca.crl', encode(ica_crl))


def build_root(key_pair, alt_key_pair=None, delta_cert=None):
    root_tbs = tbs_builder.build_root(key_pair.public_key, alt_key_pair.public_key if alt_key_pair else None)

    if delta_cert:
        root_tbs['extensions'].append(chameleon.build_delta_cert_descriptor(root_tbs, delta_cert))

    return signing.sign_tbscertificate(root_tbs, key_pair.private_key, alt_key_pair)


def build_ica(ica_key_pair, root_key_pair, alt_ica_key_pair=None, alt_root_key_pair=None, delta_cert=None):
    ica_tbs = tbs_builder.build_ica(ica_key_pair.public_key, root_key_pair.public_key,
                                    alt_ica_key_pair.public_key if alt_root_key_pair else None)

    if delta_cert:
        ica_tbs['extensions'].append(chameleon.build_delta_cert_descriptor(ica_tbs, delta_cert))

    return signing.sign_tbscertificate(ica_tbs, root_key_pair.private_key, alt_root_key_pair)


def build_ee(subject_key_pair, issuer_key_pair, alt_subject_key_pair=None, alt_issuer_key_pair=None, delta_cert=None):
    ee_tbs = tbs_builder.build_ee(subject_key_pair.public_key, issuer_key_pair.public_key,
                                  alt_subject_key_pair.public_key if alt_subject_key_pair else None)

    if delta_cert:
        ee_tbs['extensions'].append(chameleon.build_delta_cert_descriptor(ee_tbs, delta_cert))

    return signing.sign_tbscertificate(ee_tbs, issuer_key_pair.private_key, alt_issuer_key_pair)


def build_crl(key_pair, is_root, alt_key_pair=None):
    crl_tbs = tbs_builder.build_crl(is_root, key_pair.public_key,
                                    alt_key_pair.public_key if alt_key_pair else None)

    signed_crl = signing.sign_tbscertlist(crl_tbs, key_pair.private_key, alt_key_pair)

    return signed_crl


def create_key_set():
    key_oids_to_key_pairs = {}

    for oqs_alg_oid, oqs_alg_name in mappings.OID_TO_OQS_ALG_MAPPINGS.items():
        key_oids_to_key_pairs[univ.ObjectIdentifier(oqs_alg_oid)] = key.OqsPrivateKey.generate(oqs_alg_name)

    dilithium3_key_pair = key_oids_to_key_pairs[univ.ObjectIdentifier(mappings.OQS_ALG_TO_OID_MAPPINGS['Dilithium3'])]
    ec_p256_key_pair = key.EcPrivateKey.generate(ec.SECP256R1())
    key_oids_to_key_pairs[rfc5480.id_ecPublicKey] = ec_p256_key_pair

    key_oids_to_key_pairs[composite_asn1.id_composite_key] = key.KeyPair(
        key.CompositePrivateKey((dilithium3_key_pair.private_key, ec_p256_key_pair.private_key,)),
        key.CompositePublicKey(composite_asn1.id_composite_key,
                               (dilithium3_key_pair.public_key, ec_p256_key_pair.public_key))
    )

    # key_oids_to_key_pairs[composite_asn1.id_dilithium3_ecdsa_P256] = key.KeyPair(
    #    key.CompositePrivateKey((dilithium3_key_pair.private_key, ec_p256_key_pair.private_key,)),
    #    key.CompactCompositePublicKey(composite_asn1.id_dilithium3_ecdsa_P256,
    #                                  (dilithium3_key_pair.public_key, ec_p256_key_pair.public_key))
    # )

    key_oids_to_key_pairs[composite_asn1.id_dilithium3_ecdsa_P256] = key_oids_to_key_pairs[
        composite_asn1.id_composite_key]

    return key_oids_to_key_pairs


parser = argparse.ArgumentParser()
parser.add_argument('output_dir', nargs='?', default='.')

args = parser.parse_args()

os.chdir(args.output_dir)

shutil.rmtree('artifacts', True)

root_key_set = create_key_set()
ica_key_set = create_key_set()
ee_key_set = create_key_set()

for alg_oid in root_key_set.keys():
    root_cert = build_root(root_key_set[alg_oid])
    ica_cert = build_ica(ica_key_set[alg_oid], root_key_set[alg_oid])
    ee_cert = build_ee(ee_key_set[alg_oid], ica_key_set[alg_oid])
    root_crl = build_crl(root_key_set[alg_oid], True)
    ica_crl = build_crl(ica_key_set[alg_oid], False)

    persist(str(alg_oid), root_cert, root_crl, ica_cert, ica_crl, ee_cert)

root_classical_key = root_key_set[rfc5480.id_ecPublicKey]
root_alt_key = root_key_set[univ.ObjectIdentifier(mappings.OQS_ALG_TO_OID_MAPPINGS['Dilithium3'])]

ica_classical_key = ica_key_set[rfc5480.id_ecPublicKey]
ica_alt_key = ica_key_set[univ.ObjectIdentifier(mappings.OQS_ALG_TO_OID_MAPPINGS['Dilithium3'])]

ee_classical_key = ee_key_set[rfc5480.id_ecPublicKey]
ee_alt_key = ee_key_set[univ.ObjectIdentifier(mappings.OQS_ALG_TO_OID_MAPPINGS['Dilithium3'])]

root_cert = build_root(root_classical_key, root_alt_key)
ica_cert = build_ica(ica_classical_key, root_classical_key, ica_alt_key, root_alt_key)
ee_cert = build_ee(ee_classical_key, ica_classical_key, ee_alt_key, ica_alt_key)
root_crl = build_crl(root_classical_key, True, root_alt_key)
ica_crl = build_crl(ica_classical_key, False, ica_alt_key)

persist('hybrid', root_cert, root_crl, ica_cert, ica_crl, ee_cert)

root_delta_cert = build_root(root_classical_key)
ica_delta_cert = build_ica(ica_classical_key, root_classical_key)
ee_delta_cert = build_ee(ee_classical_key, ica_classical_key)

root_delta_crl = build_crl(root_classical_key, True)
ica_delta_crl = build_crl(ica_classical_key, False)

persist('delta', root_delta_cert, root_delta_crl, ica_delta_cert, ica_delta_crl, ee_delta_cert)

root_base_cert = build_root(root_alt_key, delta_cert=root_delta_cert)
ica_base_cert = build_ica(ica_alt_key, root_alt_key, delta_cert=ica_delta_cert)
ee_base_cert = build_ee(ee_alt_key, ica_alt_key, delta_cert=ee_delta_cert)

root_base_crl = build_crl(root_alt_key, True)
ica_base_crl = build_crl(ica_alt_key, False)

persist('base', root_base_cert, root_base_crl, ica_base_cert, ica_base_crl, ee_base_cert)

root_extracted_delta_cert = chameleon.get_delta_cert_from_base_cert(root_base_cert)
ica_extracted_delta_cert = chameleon.get_delta_cert_from_base_cert(ica_base_cert)
ee_extracted_delta_cert = chameleon.get_delta_cert_from_base_cert(ee_base_cert)

persist('extracted', root_extracted_delta_cert, root_delta_crl, ica_extracted_delta_cert, ica_delta_crl,
        ee_extracted_delta_cert)

