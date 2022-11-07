from pyasn1.codec.der.encoder import encode

import mappings
import signing
import tbs_builder
import os
import shutil


def persist_artifact(sig_alg_oids, subdir, filename, content):
    dir_path = os.path.join('_'.join(sig_alg_oids), subdir)
    os.makedirs(dir_path, exist_ok=True)

    path = os.path.join(dir_path, filename)

    with open(path, 'wb') as f:
        if not isinstance(content, bytes):
            content = encode(content)

        f.write(content)


def persist(sig_alg_oids,
            # root_signer,
            root_cert, root_crl,
            # ica_signer,
            ica_cert, ica_crl,
            # ee_signer,
            ee_cert):
    shutil.rmtree('_'.join(sig_alg_oids), True)

    # persist_artifact(sig_alg_oids, 'ta', 'ta_priv.der', root_signer.export_secret_key())
    persist_artifact(sig_alg_oids, 'ta', 'ta.der', encode(root_cert))

    # persist_artifact(sig_alg_oids, 'ca', 'ca_priv.der', ica_signer.export_secret_key())
    persist_artifact(sig_alg_oids, 'ca', 'ca.der', encode(ica_cert))

    # persist_artifact(sig_alg_oids, 'ee', 'cert_priv.der', ee_signer.export_secret_key())
    persist_artifact(sig_alg_oids, 'ee', 'cert.der', encode(ee_cert))

    persist_artifact(sig_alg_oids, 'crl', 'crl_ta.crl', encode(root_crl))
    persist_artifact(sig_alg_oids, 'crl', 'crl_ca.crl', encode(ica_crl))


def build_root(sig_alg_oids):
    root_signers, root_signer_public_key = signing.create_keys(sig_alg_oids)

    root_tbs = tbs_builder.build_root(sig_alg_oids, root_signer_public_key)

    signed_root = signing.sign_tbscertificate(root_signers, root_tbs)

    return root_signers, root_signer_public_key, signed_root


def build_ica(sig_alg_oids, root_signers, root_signer_public_key):
    ica_signers, ica_signer_public_key = signing.create_keys(sig_alg_oids)

    ica_tbs = tbs_builder.build_ica(sig_alg_oids, ica_signer_public_key, root_signer_public_key)

    signed_ica = signing.sign_tbscertificate(root_signers, ica_tbs)

    return ica_signers, ica_signer_public_key, signed_ica


def build_ee(sig_alg_oids, ica_signers, ica_signer_public_key):
    ee_signers, ee_signer_public_key = signing.create_keys(sig_alg_oids)

    ee_tbs = tbs_builder.build_ee(sig_alg_oids, ee_signer_public_key, ica_signer_public_key)

    signed_ee = signing.sign_tbscertificate(ica_signers, ee_tbs)

    return ee_signers, ee_signer_public_key, signed_ee


def build_crl(sig_alg_oids, signers, signer_public_key, is_root):
    crl_tbs = tbs_builder.build_crl(sig_alg_oids, is_root, signer_public_key)

    signed_crl = signing.sign_tbscertlist(signers, crl_tbs)

    return signed_crl


def generate_artifacts(sig_alg_oids):
    root_signers, root_public_key_octets, root_cert = build_root(sig_alg_oids)
    root_crl = build_crl(sig_alg_oids, root_signers, root_public_key_octets, True)
    ica_signers, ica_public_key_octets, ica_cert = build_ica(sig_alg_oids, root_signers, root_public_key_octets)
    ica_crl = build_crl(sig_alg_oids, ica_signers, ica_public_key_octets, False)
    ee_signers, ee_public_key_octets, ee_cert = build_ee(sig_alg_oids, ica_signers, ica_public_key_octets)

    persist(sig_alg_oids, root_cert, root_crl, ica_cert, ica_crl, ee_cert)


for sig_alg_oid in mappings.OID_TO_OQS_ALG_MAPPINGS.keys():
    generate_artifacts([sig_alg_oid])


COMPOSITE_TUPLES = [
    [
        mappings.OQS_ALG_TO_OID_MAPPINGS['Dilithium2'],
        mappings.OQS_ALG_TO_OID_MAPPINGS['Falcon-512'],
    ],
    [
        mappings.OQS_ALG_TO_OID_MAPPINGS['Dilithium2'],
        mappings.OQS_ALG_TO_OID_MAPPINGS['Falcon-512'],
        mappings.OQS_ALG_TO_OID_MAPPINGS['SPHINCS+-SHA256-128f-robust'],
    ]
]

for composite_tuple in COMPOSITE_TUPLES:
    generate_artifacts(composite_tuple)
