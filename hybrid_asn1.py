from pyasn1.type import univ, constraint
from pyasn1_alt_modules import rfc5280


MAX = float('inf')

id_ce_subjectAltPublicKeyInfo = univ.ObjectIdentifier('2.5.29.72')

SubjectAltPublicKeyInfo = rfc5280.SubjectPublicKeyInfo


id_ce_altSignatureAlgorithm = univ.ObjectIdentifier('2.5.29.73')

AltSignatureAlgorithm = rfc5280.AlgorithmIdentifier


id_ce_altSignatureValue = univ.ObjectIdentifier('2.5.29.74')

class AltSignatureValue(univ.BitString):
    pass
