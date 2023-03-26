from pyasn1.type import univ, namedtype
from pyasn1_alt_modules import rfc5280


def _get_namedtypes_without_signature(nts):
    component_count = len(nts)

    nts_without_signature = []

    for i in range(component_count):
        if nts[i].name != 'signature':
            nts_without_signature.append(nts[i])

    return namedtype.NamedTypes(*nts_without_signature)


MAX = float('inf')

id_ce_subjectAltPublicKeyInfo = univ.ObjectIdentifier('2.5.29.72')

SubjectAltPublicKeyInfo = rfc5280.SubjectPublicKeyInfo


id_ce_altSignatureAlgorithm = univ.ObjectIdentifier('2.5.29.73')

AltSignatureAlgorithm = rfc5280.AlgorithmIdentifier


id_ce_altSignatureValue = univ.ObjectIdentifier('2.5.29.74')

class AltSignatureValue(univ.BitString):
    pass


class PreTBSCertificate(univ.Sequence):
    pass


PreTBSCertificate.componentType = _get_namedtypes_without_signature(rfc5280.TBSCertificate.componentType)


class PreTBSCertList(univ.Sequence):
    pass


PreTBSCertList.componentType = _get_namedtypes_without_signature(rfc5280.TBSCertList.componentType)
