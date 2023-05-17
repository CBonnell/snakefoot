from pyasn1_alt_modules import rfc5652

import key


def build_content_info(oid, content):
    ci = rfc5652.ContentInfo()
    ci['contentType'] = oid
    ci['content'] = content

    return ci


def _build_signer_info(key: key.KeyPair):
    pass


def build_signed_cmp(encap_content_info, certificates=[], crls=[]):
    pass
