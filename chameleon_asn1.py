from pyasn1.type import univ, namedtype, tag
from pyasn1_alt_modules import rfc5280


id_ce_prototype_chameleon_delta_descriptor = univ.ObjectIdentifier('2.16.840.1.114027.80.6.1')

class ChameleonDeltaDescriptor(univ.Sequence):
    pass


ChameleonDeltaDescriptor.componentType = namedtype.NamedTypes(
    namedtype.NamedType('serialNumber', rfc5280.CertificateSerialNumber()),
    namedtype.OptionalNamedType('signature', rfc5280.AlgorithmIdentifier().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )),
    namedtype.OptionalNamedType('issuer', rfc5280.Name().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
    )),
    namedtype.OptionalNamedType('subject', rfc5280.Name().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
    )),
    namedtype.OptionalNamedType('subjectPublicKeyInfo', rfc5280.SubjectPublicKeyInfo().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
    )),
    namedtype.OptionalNamedType('extensions', rfc5280.Extensions().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
    )),
    namedtype.NamedType('signatureValue', univ.BitString())
)
