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
    namedtype.OptionalNamedType('validity', rfc5280.Validity().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
    )),
    namedtype.OptionalNamedType('subject', rfc5280.Name().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
    )),
    namedtype.NamedType('subjectPublicKeyInfo', rfc5280.SubjectPublicKeyInfo()),
    namedtype.OptionalNamedType('extensions', rfc5280.Extensions().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
    )),
    namedtype.NamedType('signatureValue', univ.BitString())
)


id_at_delta_certificate_request = univ.ObjectIdentifier('2.16.840.1.114027.80.6.2')


class ChameleonCertificateRequestDescriptor(univ.Sequence):
    pass


ChameleonCertificateRequestDescriptor.componentType = namedtype.NamedTypes(
    namedtype.OptionalNamedType('subject', rfc5280.Name().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )),
    namedtype.NamedType('subjectPKInfo', rfc5280.SubjectPublicKeyInfo()),
    namedtype.OptionalNamedType('extensions', rfc5280.Extensions().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
    )),
    namedtype.OptionalNamedType('signatureAlgorithm', rfc5280.AlgorithmIdentifier().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
    )),

)


id_at_delta_certificate_request_signature = univ.ObjectIdentifier('2.16.840.1.114027.80.6.3')


class ChameleonCertificateRequestSignature(univ.BitString):
    pass
