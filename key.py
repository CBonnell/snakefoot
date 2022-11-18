import binascii
from abc import ABC
from typing import NamedTuple, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5480

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

import oqs

import composite_asn1
import mappings


class KeyPair(NamedTuple):
    private_key: 'PrivateKey'
    public_key: 'PublicKey'


_KEY_OID_TO_CONSTRUCTOR = {}


def decode_spki(spki: rfc5280.SubjectPublicKeyInfo) -> 'PublicKey':
    alg_oid = spki['algorithm']['algorithm']

    spki_cons = _KEY_OID_TO_CONSTRUCTOR.get(alg_oid)

    if spki_cons is None:
        raise ValueError(f'Unknown public key algorithm "{str(alg_oid)}"')

    parameters = spki['algorithm']['parameters'] if 'parameters' in spki['algorithm'] else None

    return spki_cons(alg_oid, parameters, spki['subjectPublicKey'].asOctets())


def decode_spki_octets(octets) -> 'PublicKey':
    spki, _ = decode(octets, asn1Spec=rfc5280.SubjectPublicKeyInfo())

    return decode_spki(spki)


class PrivateKey(ABC):
    @property
    def raw_octets(self) -> bytes:
        raise NotImplementedError()

    @property
    def encoded(self) -> bytes:
        return self.raw_octets

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError()


class PublicKey(ABC):
    @property
    def key_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        raise NotImplementedError()

    @property
    def signature_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        raise NotImplementedError()

    @property
    def raw_octets(self) -> bytes:
        raise NotImplementedError()

    @property
    def encoded(self) -> bytes:
        return self.raw_octets

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def verify(self, message: bytes, signature: bytes, signature_algorithm: rfc5280.AlgorithmIdentifier) -> bool:
        raise NotImplementedError()

    @property
    def to_spki(self) -> rfc5280.SubjectPublicKeyInfo():
        spki = rfc5280.SubjectPublicKeyInfo()
        spki['algorithm'] = self.key_algorithm
        spki['subjectPublicKey'] = univ.BitString(hexValue=binascii.b2a_hex(self.encoded))

        return spki


class OqsPublicKey(PublicKey):
    def __init__(self, alg_oid: univ.ObjectIdentifier, parameters, octets: bytes):
        self._alg_name = mappings.OID_TO_OQS_ALG_MAPPINGS[str(alg_oid)]
        self._octets = octets

    @property
    def key_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        alg = rfc5280.AlgorithmIdentifier()
        alg['algorithm'] = univ.ObjectIdentifier(mappings.OQS_ALG_TO_OID_MAPPINGS[self._alg_name])

        return alg

    @property
    def signature_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        return self.key_algorithm

    @property
    def raw_octets(self):
        return self._octets

    def verify(self, message: bytes, signature: bytes, signature_algorithm: rfc5280.AlgorithmIdentifier) -> bool:
        if encode(signature_algorithm) != encode(self.signature_algorithm):
            raise ValueError('OQS Public Key and signature algorithm mismatch')

        with oqs.Signature(self._alg_name) as verifier:
            return verifier.verify(message, signature, self.raw_octets)


for oid in mappings.OID_TO_OQS_ALG_MAPPINGS.keys():
    _KEY_OID_TO_CONSTRUCTOR[univ.ObjectIdentifier(oid)] = OqsPublicKey


class OqsPrivateKey(PrivateKey):
    def __init__(self, alg_name: str, oqs_signature_obj: oqs.Signature):
        self._alg_name = alg_name
        self._backend_instance = oqs_signature_obj

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._backend_instance.free()

    @property
    def raw_octets(self) -> bytes:
        return self._backend_instance.export_secret_key()

    def sign(self, message: bytes) -> bytes:
        return self._backend_instance.sign(message)

    @staticmethod
    def generate(alg_name):
        backend_instance = oqs.Signature(alg_name)
        public_key = backend_instance.generate_keypair()

        alg_oid = univ.ObjectIdentifier(mappings.OQS_ALG_TO_OID_MAPPINGS[alg_name])

        return KeyPair(OqsPrivateKey(alg_name, backend_instance), OqsPublicKey(alg_oid, None, public_key))


_OID_TO_CURVE = {
    rfc5480.secp256r1: ec.SECP256R1,
    rfc5480.secp384r1: ec.SECP384R1,
    rfc5480.secp521r1: ec.SECP521R1,
}

_CURVE_TO_OID = {v: k for k, v in _OID_TO_CURVE.items()}

_CURVE_TO_HASH_CLS = {
    ec.SECP256R1: hashes.SHA256,
    ec.SECP384R1: hashes.SHA384,
    ec.SECP521R1: hashes.SHA512,
}

_CURVE_TO_SIG_ALG = {
    ec.SECP256R1: rfc5480.ecdsa_with_SHA256,
    ec.SECP384R1: rfc5480.ecdsa_with_SHA384,
    ec.SECP521R1: rfc5480.ecdsa_with_SHA512,
}


class EcPublicKey(PublicKey):
    def __init__(self, alg_oid, parameters, octets: bytes):
        self._octets = octets
        self._curve_oid, _ = decode(parameters, asn1Spec=univ.ObjectIdentifier())

        curve_cls = _OID_TO_CURVE[self._curve_oid]

        self._backend_instance = ec.EllipticCurvePublicKey.from_encoded_point(curve_cls(), octets)

    @property
    def key_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        alg = rfc5280.AlgorithmIdentifier()
        alg['algorithm'] = rfc5480.id_ecPublicKey
        alg['parameters'] = encode(self._curve_oid)

        return alg

    @property
    def signature_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        alg = rfc5280.AlgorithmIdentifier()
        alg['algorithm'] = _CURVE_TO_SIG_ALG[type(self._backend_instance.curve)]

        return alg

    @property
    def raw_octets(self) -> bytes:
        return self._octets

    @property
    def encoded(self) -> bytes:
        return self._backend_instance.public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

    def verify(self, message: bytes, signature: bytes, signature_algorithm: rfc5280.AlgorithmIdentifier) -> bool:
        if encode(signature_algorithm) != encode(self.signature_algorithm):
            raise ValueError('ECDSA key and signature algorithm mismatch')

        h_cls = _CURVE_TO_HASH_CLS[type(self._backend_instance.curve)]

        try:
            self._backend_instance.verify(signature, message, ec.ECDSA(h_cls()))

            return True
        except InvalidSignature:
            return False


_KEY_OID_TO_CONSTRUCTOR[rfc5480.id_ecPublicKey] = EcPublicKey


class EcPrivateKey(PrivateKey):
    def __init__(self, cryptography_obj: ec.EllipticCurvePrivateKey):
        self._backend_instance = cryptography_obj

    @property
    def raw_octets(self) -> bytes:
        raise NotImplementedError()

    def sign(self, message: bytes) -> bytes:
        h_cls = _CURVE_TO_HASH_CLS[type(self._backend_instance.curve)]

        return self._backend_instance.sign(message, ec.ECDSA(h_cls()))

    @staticmethod
    def generate(curve: ec.EllipticCurve) -> KeyPair:
        crypto_private_key = ec.generate_private_key(curve)
        crypto_public_key = crypto_private_key.public_key()
        crypto_public_key_octets = crypto_public_key.public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

        return KeyPair(
            EcPrivateKey(crypto_private_key),
            EcPublicKey(rfc5480.id_ecPublicKey, encode(_CURVE_TO_OID[type(curve)]), crypto_public_key_octets))


class ExplicitCompositeKeyAlgorithm(NamedTuple):
    key_algorithms: Sequence[rfc5280.AlgorithmIdentifier]
    signature_algorithms: Sequence[rfc5280.AlgorithmIdentifier]


EXPLICIT_KEY_OID_TO_ALGORITHM_MAPPINGS = {}


def create_dilithium3_ecdsa_p256_mapping():
    dilithium3_alg = rfc5280.AlgorithmIdentifier()
    dilithium3_alg['algorithm'] = univ.ObjectIdentifier(mappings.OQS_ALG_TO_OID_MAPPINGS['Dilithium3'])

    ecdsa_p256_key_alg = rfc5280.AlgorithmIdentifier()
    ecdsa_p256_key_alg['algorithm'] = rfc5480.id_ecPublicKey
    ecdsa_p256_key_alg['parameters'] = encode(rfc5480.secp256r1)

    ecdsa_with_sha256_sig_alg = rfc5280.AlgorithmIdentifier()
    ecdsa_with_sha256_sig_alg['algorithm'] = rfc5480.ecdsa_with_SHA256

    return ExplicitCompositeKeyAlgorithm(
        (dilithium3_alg, ecdsa_p256_key_alg,),
        (dilithium3_alg, ecdsa_with_sha256_sig_alg,)
    )


EXPLICIT_KEY_OID_TO_ALGORITHM_MAPPINGS[composite_asn1.id_dilithium3_ecdsa_P256] = create_dilithium3_ecdsa_p256_mapping()


class CompositePublicKey(PublicKey):
    def __init__(self, alg_oid, public_keys):
        self._alg_oid = alg_oid
        self._public_keys = public_keys
        self._octets = self.encoded

    @classmethod
    def from_octets(cls, alg_oid, parameters, octets):
        decoded, _ = decode(octets, asn1Spec=composite_asn1.CompositePublicKey())

        public_keys = [decode_spki(s) for s in decoded]

        return CompositePublicKey.from_public_keys(alg_oid, public_keys)

    @classmethod
    def from_public_keys(cls, alg_oid, public_keys):
        explicit_composite_mapping = EXPLICIT_KEY_OID_TO_ALGORITHM_MAPPINGS.get(alg_oid)

        if explicit_composite_mapping is not None:
            # TODO: verify explicit OID and public key consistency
            pass
        elif any((s.key_algorithm['algorithm'] == composite_asn1.id_composite_key for s in public_keys)):
            raise ValueError('Nested composite keys are prohibited')

        return CompositePublicKey(alg_oid, public_keys)

    @property
    def key_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        alg = rfc5280.AlgorithmIdentifier()
        alg['algorithm'] = self._alg_oid

        return alg

    @property
    def signature_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        alg = rfc5280.AlgorithmIdentifier()
        alg['algorithm'] = composite_asn1.id_alg_composite

        params = composite_asn1.CompositeParams()

        for key in self._public_keys:
            alg_id = key.signature_algorithm
            params.append(alg_id)

        alg['parameters'] = encode(params)

        return alg

    @property
    def raw_octets(self) -> bytes:
        return self._octets

    @property
    def encoded(self) -> bytes:
        comp_key = composite_asn1.CompositePublicKey()

        for key in self._public_keys:
            comp_key.append(key.to_spki)

        return encode(comp_key)

    def verify(self, message: bytes, signature: bytes, signature_algorithm: rfc5280.AlgorithmIdentifier) -> bool:
        if signature_algorithm['algorithm'] != composite_asn1.id_alg_composite:
            raise ValueError('Composite public key and signature algorithm mismatch')

        sig_params, _ = decode(signature_algorithm['parameters'], asn1Spec=composite_asn1.CompositeParams())

        decoded, _ = decode(signature, asn1Spec=composite_asn1.CompositeSignatureValue())

        for key, sig_value, sig_alg in zip(self._public_keys, decoded, sig_params):
            if not key.verify(message, sig_value.asOctets(), sig_alg):
                return False

        return True


_KEY_OID_TO_CONSTRUCTOR[composite_asn1.id_composite_key] = CompositePublicKey.from_octets
_KEY_OID_TO_CONSTRUCTOR[composite_asn1.id_dilithium3_ecdsa_P256] = CompositePublicKey.from_octets


class CompositePrivateKey(PrivateKey):
    def __init__(self, private_keys: Sequence[PrivateKey]):
        self._private_keys = private_keys

    @property
    def raw_octets(self) -> bytes:
        raise NotImplementedError()

    def sign(self, message: bytes) -> bytes:
        comp_sig = composite_asn1.CompositeSignatureValue()

        for key in self._private_keys:
            value = univ.BitString(hexValue=binascii.b2a_hex(key.sign(message)))

            comp_sig.append(value)

        return encode(comp_sig)
