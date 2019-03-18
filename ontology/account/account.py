import math
import base64
import base58
import functools

from ontology.crypto.curve import Curve
from ontology.crypto.digest import Digest
from ontology.crypto.scrypt import Scrypt
from ontology.common.define import DID_ONT
from ontology.common.address import Address
from ontology.crypto.key_type import KeyType
from ontology.crypto.signature import Signature
from ontology.crypto.aes_handler import AESHandler
from ontology.io.binary_writer import BinaryWriter
from ontology.io.memory_stream import StreamManager
from ontology.exception.error_code import ErrorCode
from ontology.exception.exception import SDKException
from ontology.crypto.signature_scheme import SignatureScheme
from ontology.crypto.signature_handler import SignatureHandler

_SHA256 = SignatureScheme.SHA256withECDSA
_SHA3_224 = SignatureScheme.SHA3_224withECDSA
_SHA3_384 = SignatureScheme.SHA3_384withECDSA
_SHA512 = SignatureScheme.SHA512withECDSA

SUPPORTED_SCHEMES = [_SHA256, _SHA3_224, _SHA3_384, _SHA512]
SUPPORTED_KEY_TYPES = [KeyType.ECDSA]


class Account(object):
    """
    Account - Ontology account interface

    :parameter private_key: private_key
    :parameter scheme: SignatureScheme
    """

    def __init__(self, pri_key: bytearray or bytes, scheme: SignatureScheme = _SHA256):
        """
        :param private_key: private key
        :type private_key: bytearray or bytes
        :param scheme: Signature Scheme
        :type scheme: SignatureScheme
        """
        if scheme not in SUPPORTED_SCHEMES:
            raise NotImplementedError(f'Signature Scheme must be {iter(*SUPPORTED_SCHEMES)}') from scheme

        self._scheme = SignatureScheme(scheme)
        self._handle = SignatureHandler(scheme)

        if not isinstance(pri_key, bytearray or bytes):
            raise TypeError('WIF is an array, AES-G/CM is bytes') from pri_key
        elif not math.log(len(pri_key).bit_length(), 32).is_integer():
            raise BytesWarning('WIF is base58 encoded, AES-G/CM is base64 encoded') from pri_key

        self._sign = functools.partial(self._handle.generate_signature)
        self.__sign_ok = functools.partial(self._handle.verify_signature)

        _pub_key = Signature.ec_get_public_key_by_private_key # TODO: shorten
        self.pub_key = _pub_key(pri_key, curve_name=Curve.P256)

        __address = Address.address_from_bytes_pubkey(self.pub_key)

        self.address = base58.b58encode(bytes.fromhex(__address))

        self.__private_key = pri_key # TODO expose on needed basis
        self.ont_id = DID_ONT + self.address.base58

    def generate_signature(self, msg: bytes) -> bytes:
        """
        Generates a signed message signed with account key pair.
        :param msg: message to sign
        :type msg: bytes
        :return: signed message
        :rtype: Signature
        """
        signature = Signature(self._scheme, self._sign(self.get_private_key_hex(), msg)).to_bytes()
        if not self.__sign_ok(self.get_public_key_bytes(), msg, signature):
            raise ArithmeticError('Invalid key pair')
        return signature

    def export_gcm_encrypted_private_key(self, password: str, salt: str, n: int = 16384) -> str:
        """
        This interface is used to export an AES algorithm encrypted private key with the mode of GCM.

        :param password: the secret pass phrase to generate the keys from.
        :param salt: A string to use for better protection from dictionary attacks.
                      This value does not need to be kept secret, but it should be randomly chosen for each derivation.
                      It is recommended to be at least 8 bytes long.
        :param n: CPU/memory cost parameter. It must be a power of 2 and less than 2**32
        :return: an gcm encrypted private key in the form of string.
        """
        r, p, dk_len = 8, 8, 64
        scrypt = Scrypt(n, r, p, dk_len)
        derived_key = scrypt.generate_kd(password, salt)
        iv = derived_key[0:12]
        key = derived_key[32:64]
        hdr = self.address
        mac_tag, cipher_text = AESHandler.aes_gcm_encrypt_with_iv(self.__private_key, hdr, key, iv)
        encrypted_key = bytes.hex(cipher_text) + bytes.hex(mac_tag)
        encrypted_key_str = base64.b64encode(bytes.fromhex(encrypted_key))
        return encrypted_key_str.decode('utf-8')

    @staticmethod
    def get_gcm_decoded_private_key(encrypted_key_str: str, password: str, b58_address: str, salt: str, n: int,
                                    scheme: SignatureScheme) -> str:
        """
        This interface is used to decrypt an private key which has been encrypted.

        :param encrypted_key_str: an gcm encrypted private key in the form of string.
        :param password: the secret pass phrase to generate the keys from.
        :param b58_address: a base58 encode address which should be correspond with the private key.
        :param salt: a string to use for better protection from dictionary attacks.
        :param n: CPU/memory cost parameter.
        :param scheme: the signature scheme.
        :return: a private key in the form of string.
        """
        r, p, dk_len = 8, 8, 64
        scrypt = Scrypt(n, r, p, dk_len)
        derived_key = scrypt.generate_kd(password, salt)
        iv = derived_key[0:12]
        key = derived_key[32:64]
        encrypted_key = base64.b64decode(encrypted_key_str).hex()
        mac_tag = bytes.fromhex(encrypted_key[64:96])
        cipher_text = bytes.fromhex(encrypted_key[0:64])
        private_key = AESHandler.aes_gcm_decrypt_with_iv(cipher_text, b58_address.encode(), mac_tag, key, iv)
        if len(private_key) == 0:
            raise SDKException(ErrorCode.decrypt_encrypted_private_key_error)
        if Account(private_key, scheme).address != b58_address:
            raise SDKException(ErrorCode.other_error('Address error.'))
        return private_key.hex()

    def get_public_key_serialize(self):
        stream = StreamManager.get_stream()
        writer = BinaryWriter(stream)
        writer.write_var_bytes(self.pub_key)
        stream.flush()
        bytes_stream = stream.hexlify()
        StreamManager.release_stream(stream)
        return bytes_stream

    def get_private_key_bytes(self) -> bytes:
        """
        This interface is used to get the private key in the form of bytes.

        :return: the private key in the form of bytes.
        """
        return self.__private_key

    def get_private_key_hex(self) -> str:
        """
        This interface is used to get the account's hexadecimal public key in the form of string.

        :return: the hexadecimal public key in the form of string.
        """
        return bytes.hex(self.__private_key)

    def get_public_key_bytes(self) -> bytes:
        """
        This interface is used to get the public key in the form of bytes.

        :return: the public key in the form of bytes.
        """
        return self.pub_key

    def get_public_key_bytearray(self) -> bytearray:
        """
        This interface is used to get the public key in the form of bytearray.

        :return: the public key in the form of bytearray.
        """
        return bytearray(self.pub_key)

    def get_public_key_hex(self) -> str:
        """
        This interface is used to get the account's hexadecimal public key in the form of string.

        :return: the hexadecimal public key in the form of string.
        """
        return bytes.hex(self.pub_key)

    def export_wif(self) -> str:
        """
        This interface is used to get export ECDSA private key in the form of WIF which
        is a way to encoding an ECDSA private key and make it easier to copy.

        :return: a WIF encode private key.
        """
        data = b''.join([b'\x80', self.__private_key, b'\01'])
        checksum = Digest.hash256(data[0:34])
        wif = base58.b58encode(b''.join([data, checksum[0:4]]))
        return wif.decode('ascii')

    @staticmethod
    def get_private_key_from_wif(wif: str) -> bytes:
        """
        This interface is used to decode a WIF encode ECDSA private key.

        :param wif: a WIF encode private key.
        :return: a ECDSA private key in the form of bytes.
        """
        if wif is None or wif is "":
            raise Exception("none wif")
        data = base58.b58decode(wif)
        if len(data) != 38 or data[0] != 0x80 or data[33] != 0x01:
            raise Exception("wif wrong")
        checksum = Digest.hash256(data[0:34])
        for i in range(4):
            if data[len(data) - 4 + i] != checksum[i]:
                raise Exception("wif wrong")
        return data[1:33]
