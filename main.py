from pyasn1.codec.der.encoder import encode

import mappings
import signing
import tbs_builder
import os
import shutil


def persist_artifact(sig_alg_oid, subdir, filename, content):
    path = os.path.join(sig_alg_oid, subdir, filename)

    os.makedirs(os.path.join(sig_alg_oid, subdir), exist_ok=True)

    with open(path, 'wb') as f:
        if not isinstance(content, bytes):
            content = encode(content)

        f.write(content)


def persist(sig_alg_name,
            root_signer, root_cert, root_crl,
            ica_signer, ica_cert, ica_crl,
            ee_signer, ee_cert):
    sig_alg_oid = mappings.ALG_TO_OID_MAPPINGS[sig_alg_name]

    shutil.rmtree(sig_alg_oid, True)

    persist_artifact(sig_alg_oid, 'ta', 'ta_priv.der', root_signer.export_secret_key())
    persist_artifact(sig_alg_oid, 'ta', 'ta.der', encode(root_cert))

    persist_artifact(sig_alg_oid, 'ca', 'ca_priv.der', ica_signer.export_secret_key())
    persist_artifact(sig_alg_oid, 'ca', 'ca.der', encode(ica_cert))

    persist_artifact(sig_alg_oid, 'ee', 'cert_priv.der', ee_signer.export_secret_key())
    persist_artifact(sig_alg_oid, 'ee', 'cert.der', encode(ee_cert))

    persist_artifact(sig_alg_oid, 'crl', 'crl_ta.crl', encode(root_crl))
    persist_artifact(sig_alg_oid, 'crl', 'crl_ca.crl', encode(ica_crl))


def build_root(sig_alg_name):
    root_signer, root_signer_public_key = signing.create_key(sig_alg_name)

    root_tbs = tbs_builder.build_root(sig_alg_name, root_signer_public_key)

    signed_root = signing.sign_tbscertificate(root_signer, root_tbs)

    return root_signer, root_signer_public_key, signed_root


def build_ica(sig_alg_name, root_signer, root_signer_public_key):
    ica_signer, ica_signer_public_key = signing.create_key(sig_alg_name)

    ica_tbs = tbs_builder.build_ica(sig_alg_name, ica_signer_public_key, root_signer_public_key)

    signed_ica = signing.sign_tbscertificate(root_signer, ica_tbs)

    return ica_signer, ica_signer_public_key, signed_ica


def build_ee(sig_alg_name, ica_signer, ica_signer_public_key):
    ee_signer, ee_signer_public_key = signing.create_key(sig_alg_name)

    ee_tbs = tbs_builder.build_ee(sig_alg_name, ee_signer_public_key, ica_signer_public_key)

    signed_ee = signing.sign_tbscertificate(ica_signer, ee_tbs)

    return ee_signer, ee_signer_public_key, signed_ee


def build_crl(sig_alg_name, signer, signer_public_key, is_root):
    crl_tbs = tbs_builder.build_crl(sig_alg_name, is_root, signer_public_key)

    signed_crl = signing.sign_tbscertlist(signer, crl_tbs)

    return signed_crl


for sig_alg_name in mappings.ALG_TO_OID_MAPPINGS.keys():
    root_signer, root_public_key_octets, root_cert = build_root(sig_alg_name)
    root_crl = build_crl(sig_alg_name, root_signer, root_public_key_octets, True)
    ica_signer, ica_public_key_octets, ica_cert = build_ica(sig_alg_name, root_signer, root_public_key_octets)
    ica_crl = build_crl(sig_alg_name, ica_signer, ica_public_key_octets, False)
    ee_signer, ee_public_key_octets, ee_cert = build_ee(sig_alg_name, ica_signer, ica_public_key_octets)


    persist(sig_alg_name, root_signer, root_cert, root_crl, ica_signer, ica_cert, ica_crl, ee_signer, ee_cert)
