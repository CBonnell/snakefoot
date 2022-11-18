from pyasn1.type import univ, constraint
from pyasn1_alt_modules import rfc5280


MAX = float('inf')


id_alg_composite = univ.ObjectIdentifier('1.3.6.1.4.1.18227.2.1')


class CompositeSignatureValue(univ.SequenceOf):
    pass


CompositeSignatureValue.componentType = univ.BitString()
CompositeSignatureValue.sizeSpec = constraint.ValueSizeConstraint(2, MAX)


class CompositeParams(univ.SequenceOf):
    pass


CompositeParams.componentType = rfc5280.AlgorithmIdentifier()
CompositeParams.sizeSpec = constraint.ValueSizeConstraint(2, MAX)


id_composite_key = univ.ObjectIdentifier('2.16.840.1.114027.80.4.1')


class CompositePublicKey(univ.SequenceOf):
    pass


CompositePublicKey.componentType = rfc5280.SubjectPublicKeyInfo()
CompositePublicKey.sizeSpec = constraint.ValueSizeConstraint(2, MAX)


id_dilithium3_ecdsa_P256 = univ.ObjectIdentifier('2.16.840.1.114027.80.5.1')
