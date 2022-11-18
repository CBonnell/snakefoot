from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5480

import composite_asn1
import key
import mappings
import signing
import tbs_builder
import os
import shutil


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


def build_root(key_pair):
    root_tbs = tbs_builder.build_root(key_pair.public_key)

    return signing.sign_tbscertificate(key_pair.private_key, root_tbs)


def build_ica(ica_key_pair, root_key_pair):
    ica_tbs = tbs_builder.build_ica(ica_key_pair.public_key, root_key_pair.public_key)

    return signing.sign_tbscertificate(root_key_pair.private_key, ica_tbs)


def build_ee(subject_key_pair, issuer_key_pair):
    ee_tbs = tbs_builder.build_ee(subject_key_pair.public_key, issuer_key_pair.public_key)

    return signing.sign_tbscertificate(issuer_key_pair.private_key, ee_tbs)


def build_crl(key_pair, is_root):
    crl_tbs = tbs_builder.build_crl(is_root, key_pair.public_key)

    signed_crl = signing.sign_tbscertlist(key_pair.private_key, crl_tbs)

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

    key_oids_to_key_pairs[composite_asn1.id_dilithium3_ecdsa_P256] = key_oids_to_key_pairs[
        composite_asn1.id_composite_key]

    return key_oids_to_key_pairs


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
