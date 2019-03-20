import base58
import typing
import ontology.vm as ont_vm

from common.error import SDKError
from common.exception import SDKException
from crypto.digest import Digest
from core.program import ProgramBuilder
from vm.params_builder import ParamsBuilder


class Address(object):
    __COIN_VERSION = b'\x17'

    def __init__(self, script_hash: bytes):
        if not isinstance(script_hash, bytes):
            raise SDKException(SDKError.other_error('Invalid script hash.'))
        elif len(script_hash) != 20:
            raise SDKException(SDKError.other_error('Invalid script hash.'))
        self.ZERO = script_hash

    @staticmethod
    def to_script_hash(byte_script) -> bytes:
        return Digest.hash160(msg=byte_script, is_hex=False)

    @staticmethod
    def address_from_bytes_pubkey(public_key: bytes):
        builder = ParamsBuilder()
        builder.emit_push_bytearray(bytearray(public_key))
        builder.emit(ont_vm.CHECKSIG)
        addr = Address(Address.to_script_hash(builder.to_bytes()))
        return addr

    @staticmethod
    def address_from_multi_pub_keys(m: int, pub_keys: typing.List[bytes]):
        return Address(Address.to_script_hash(ProgramBuilder.program_from_multi_pubkey(m, pub_keys)))

    @staticmethod
    def b58_address_from_multi_pub_keys(m: int, pub_keys: typing.List[bytes]):
        return Address(Address.to_script_hash(ProgramBuilder.program_from_multi_pubkey(m, pub_keys))).b58encode()

    @staticmethod
    def address_from_vm_code(code: str):
        """
        generate contract address from avm bytecode.
        :param code: str
        :return: Address
        """
        script_hash = Address.to_script_hash(bytearray.fromhex(code))[::-1]
        return Address(script_hash)

    def b58encode(self):
        script_builder = Address.__COIN_VERSION + self.ZERO
        c256 = Digest.hash256(script_builder)[0:4]
        out_bytes = script_builder + c256
        return base58.b58encode(out_bytes).decode('utf-8')

    def to_bytes(self):
        return self.ZERO

    def to_bytearray(self):
        return bytearray(self.ZERO)

    def to_hex_str(self):
        return bytes.hex(self.ZERO)

    def to_reverse_hex_str(self):
        bytearray_zero = bytearray(self.ZERO)
        bytearray_zero.reverse()
        return bytearray.hex(bytearray_zero)

    @staticmethod
    def b58decode(address: str):
        data = base58.b58decode(address)
        if len(data) != 25:
            raise SDKException(SDKError.param_error)
        if data[0] != int.from_bytes(Address.__COIN_VERSION, "little"):
            raise SDKException(SDKError.param_error)
        checksum = Digest.hash256(data[0:21])
        if data[21:25] != checksum[0:4]:
            raise SDKException(SDKError.param_error)
        return Address(data[1:21])
