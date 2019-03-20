from Cryptodome.Random.random import choice

from ontology.service.service import Service
from ontology.smart_contract.neo_vm import NeoVm
from ontology.exception import SDKException, ErrorCode
from ontology.smart_contract.native_vm import NativeVm
from ontology.network.websocket import WebsocketClient
from ontology.wallet.wallet_manager import WalletManager
from ontology.crypto.signature_scheme import SignatureScheme
from ontology.network.rpc import RpcClient, TEST_RPC_ADDRESS, MAIN_RPC_ADDRESS
from ontology.network.restful import RestfulClient, TEST_RESTFUL_ADDRESS, MAIN_RESTFUL_ADDRESS


class _Singleton(type):
    def __init__(cls, *args, **kwargs):
        cls.__instance = None
        super().__init__(*args, **kwargs)

    def __call__(cls, *args, **kwargs):
        if cls.__instance is None:
            cls.__instance = super().__call__(*args, **kwargs)
            return cls.__instance
        else:
            return cls.__instance


class OntologySdk(metaclass=_Singleton):
    def __init__(self, rpc_address: str = '', restful_address: str = '', ws_address: str = '', sig_svr_address='',
                 default_signature_scheme: SignatureScheme = SignatureScheme.SHA256withECDSA):
        if not isinstance(default_signature_scheme, SignatureScheme):
            raise SDKException(ErrorCode.param_err('SignatureScheme object is required.'))
        self.__rpc = RpcClient(rpc_address)
        self.__restful = RestfulClient(restful_address)
        self.__websocket = WebsocketClient(ws_address)
        self.__native_vm = NativeVm(self)
        self.__neo_vm = NeoVm(self)
        self.__service = Service(self)
        self.__wallet_manager = WalletManager()
        self.__default_signature_scheme = default_signature_scheme

    def get_network(self) -> RpcClient or RestfulClient:
        if self.__rpc.get_address() != '':
            return self.__rpc
        elif self.__restful.get_address() != '':
            return self.__restful
        else:
            raise SDKException(ErrorCode.other_error('Invalid network instance.'))

    @property
    def wallet_manager(self):
        if self.__wallet_manager is None:
            self.__wallet_manager = WalletManager()
        return self.__wallet_manager

    @wallet_manager.setter
    def wallet_manager(self, wallet_manager: WalletManager):
        if isinstance(self.wallet_manager, WalletManager):
            self.__wallet_manager = wallet_manager
        else:
            raise SDKException(ErrorCode.other_error('Invalid WalletManager instance'))

    @property
    def default_signature_scheme(self):
        if self.__default_signature_scheme is None:
            self.__default_signature_scheme = SignatureScheme.SHA256withECDSA
        return self.__default_signature_scheme

    @default_signature_scheme.setter
    def default_signature_scheme(self, scheme: SignatureScheme):
        if isinstance(scheme, SignatureScheme):
            self.__default_signature_scheme = scheme
            self.__wallet_manager.set_signature_scheme(scheme)
        else:
            raise SDKException(ErrorCode.other_error('Invalid signature scheme'))

    @property
    def rpc(self) -> RpcClient:
        return self.__rpc

    @rpc.setter
    def rpc(self, rpc_client: RpcClient):
        if isinstance(rpc_client, RpcClient):
            self.__rpc = rpc_client

    @property
    def restful(self) -> RestfulClient:
        return self.__restful

    @restful.setter
    def restful(self, restful_client: RestfulClient):
        if isinstance(restful_client, RestfulClient):
            self.__restful = restful_client

    @property
    def websocket(self) -> WebsocketClient:
        return self.__websocket

    @websocket.setter
    def websocket(self, websocket_client: WebsocketClient):
        if isinstance(websocket_client, WebsocketClient):
            self.__websocket = websocket_client

    @property
    def native_vm(self):
        return self.__native_vm

    @property
    def neo_vm(self):
        return self.__neo_vm

    @property
    def service(self):
        return self.__service

    def set_rpc_address(self, rpc_address: str):
        if isinstance(self.__rpc, RpcClient):
            self.__rpc.set_address(rpc_address)
        else:
            self.__rpc = RpcClient(rpc_address)

    def get_rpc_address(self):
        if self.__rpc is None:
            return ''
        return self.__rpc.get_address()

    @staticmethod
    def get_random_test_rpc_address():
        return choice(TEST_RPC_ADDRESS)

    @staticmethod
    def get_random_main_rpc_address():
        return choice(MAIN_RPC_ADDRESS)

    def set_restful_address(self, restful_address: str):
        if isinstance(self.__restful, RestfulClient):
            self.__restful.set_address(restful_address)
        else:
            self.__restful = RestfulClient(restful_address)

    def get_restful_address(self):
        if not isinstance(self.__restful, RestfulClient):
            return ''
        return self.__restful.get_address()

    @staticmethod
    def get_random_test_restful_address():
        choice(TEST_RESTFUL_ADDRESS)

    @staticmethod
    def get_random_main_restful_address():
        return choice(MAIN_RESTFUL_ADDRESS)

    @staticmethod
    def get_test_net_restful_address_list():
        return TEST_RESTFUL_ADDRESS

    @staticmethod
    def get_main_net_restful_address_list():
        return MAIN_RESTFUL_ADDRESS

    def set_websocket_address(self, websocket_address: str):
        if isinstance(self.__websocket, WebsocketClient):
            self.__websocket.set_address(websocket_address)
        else:
            self.__websocket = WebsocketClient(websocket_address)

    def get_websocket_address(self):
        if not isinstance(self.__websocket, WebsocketClient):
            return ''
        return self.__websocket.get_address()

'''
from functools import wraps
from inspect import signature
from typing import List

from .account import Account
from .address import Address
from .error import SDKError
from .exception import SDKException, SDKRuntimeException

__all__ = (
    "Account",
    "Address",
    "SDKException",
    "SDKError",
    "SDKRuntimeException",
)

from common.define import DID_ONT
from common.account import Account
from common.address import Address
from core.transaction import Transaction
from wallet.identity import Identity
from common.exception import SDKException, ErrorCode

from vm import PUSHM1, PUSH0
from io.binary_reader import BinaryReader
from io.memory_stream import StreamManager
from smart_contract.neo_contract.abi.struct_type import Struct
from smart_contract.neo_contract.abi.build_params import BuildParams

# TODO: move to common/__init__.py


# NeoVM invokes a smart contract return type

NEOVM_TYPE_BOOL = 1
NEOVM_TYPE_INTEGER = 2
NEOVM_TYPE_BYTE_ARRAY = 3
NEOVM_TYPE_STRING = 4
UINT256_SIZE = 32

VERSION_TRANSACTION = b'\x00'
VERSION_CONTRACT_ONT = b'\x00'
VERSION_CONTRACT_ONG = b'\x00'

NATIVE_TRANSFER = 'transfer'
NATIVE_TRANSFER_FROM = 'transferFrom'
NATIVE_APPROVE = 'approve'
NATIVE_ALLOWANCE = 'allowance'
DID_ONT = 'did:ont:'

__version__ = '0.1'

__any__ = (
    "Account",
    "Address",
    "Transaction",
    "Identity",
    "SDKException",
    "ErrorCode",
    "DID_ONT",
    "Address",
    "BinaryReader",
    "StreamManager",
    "Struct",
    "BuildParams",
)


def check_ont_id(func):
    if __debug__ is False:
        return func

    sig = signature(func)

    @wraps(func)
    def wrapper(*args, **kwargs):
        bound_values = sig.bind(*args, **kwargs)
        ont_id = bound_values.arguments.get('ont_id')
        if not isinstance(ont_id, str):
            raise SDKException(ErrorCode.require_str_params)
        if not ont_id.startswith(DID_ONT):
            raise SDKException(ErrorCode.invalid_ont_id_format(ont_id))
        return func(*args, **kwargs)

    return wrapper


def type_assert(*ty_args, **ty_kwargs):
    def decorate(func):
        if __debug__ is False:
            return func
        sig = signature(func)
        bound_types = sig.bind_partial(*ty_args, **ty_kwargs).arguments

        @wraps(func)
        def wrapper(*args, **kwargs):
            bound_values = sig.bind(*args, **kwargs)
            for name, value in bound_values.arguments.items():
                if name in bound_types:
                    type_name = bound_types[name]
                    if not isinstance(value, type_name):
                        raise SDKException(ErrorCode.params_type_error(f'the type of parameter should be {type_name}'))
            return func(*args, **kwargs)

        return wrapper

    return decorate


class ContractDataParser(object):
    @staticmethod
    def to_bool(hex_str) -> bool:
        if len(hex_str) != 2:
            raise SDKException(ErrorCode.other_error('invalid str'))
        return bool(hex_str)

    @staticmethod
    def to_int(hex_str: str) -> int:
        try:
            array = bytearray.fromhex(hex_str)
        except ValueError as e:
            raise SDKException(ErrorCode.other_error(e.args[0]))
        array.reverse()
        try:
            num = int(bytearray.hex(array), 16)
        except ValueError as e:
            raise SDKException(ErrorCode.other_error(e.args[0]))
        return num

    @staticmethod
    def op_code_to_int(op_code: str):
        if op_code.lower() == '4f':
            return -1
        elif op_code == '00':
            return 0
        elif 80 < int(op_code, base=16) < 103:
            return int(op_code, base=16) - 80
        else:
            op_code = bytearray.fromhex(op_code)
            stream = StreamManager.get_stream(op_code)
            reader = BinaryReader(stream)
            op_code = bytearray(reader.read_var_bytes())
            return ContractDataParser.neo_bytearray_to_big_int(op_code)

    @staticmethod
    def to_int_list(hex_str_list: list) -> List[int]:
        for index, item in enumerate(hex_str_list):
            if isinstance(item, list):
                hex_str_list[index] = ContractDataParser.to_int_list(item)
            elif isinstance(item, str):
                hex_str_list[index] = ContractDataParser.to_int(item)
            else:
                raise SDKException(ErrorCode.other_error('Invalid data.'))
        return hex_str_list

    @staticmethod
    def to_bytes(hex_str: str) -> bytes:
        try:
            bytes_str = bytes.fromhex(hex_str)
        except ValueError as e:
            raise SDKException(ErrorCode.other_error(e.args[0]))
        return bytes_str

    @staticmethod
    def to_bytes_list(hex_str_list: list) -> List[bytes]:
        for index, item in enumerate(hex_str_list):
            if isinstance(item, list):
                hex_str_list[index] = ContractDataParser.to_bytes_list(item)
            elif isinstance(item, str):
                hex_str_list[index] = ContractDataParser.to_bytes(item)
            else:
                raise SDKException(ErrorCode.other_error('invalid data'))
        return hex_str_list

    @staticmethod
    def to_reserve_hex_str(hex_str: str) -> str:
        hex_str = ''.join(reversed([hex_str[i:i + 2] for i in range(0, len(hex_str), 2)]))
        return hex_str

    @staticmethod
    def to_utf8_str(ascii_str: str) -> str:
        try:
            utf8_str = bytes.fromhex(ascii_str)
            utf8_str = utf8_str.decode('utf-8')
        except ValueError as e:
            raise SDKException(ErrorCode.other_error(e.args[0]))
        return utf8_str

    @staticmethod
    def to_hex_str(ascii_str: str) -> str:
        hex_str = bytes.fromhex(ascii_str)
        return hex_str.decode('ascii')

    @staticmethod
    def to_utf8_str_list(hex_str_list: list) -> List[bytes]:
        for index, item in enumerate(hex_str_list):
            if isinstance(item, list):
                hex_str_list[index] = ContractDataParser.to_utf8_str_list(item)
            elif isinstance(item, str):
                hex_str_list[index] = ContractDataParser.to_utf8_str(item)
            else:
                raise SDKException(ErrorCode.other_error('invalid data'))
        return hex_str_list

    @staticmethod
    def to_b58_address(hex_address: str) -> str:
        try:
            bytes_address = bytes.fromhex(hex_address)
        except ValueError as e:
            raise SDKException(ErrorCode.other_error(e.args[0]))
        address = Address(bytes_address)
        return address.b58encode()

    @staticmethod
    def to_b58_address_list(hex_str_list: list) -> List[bytes]:
        for index, item in enumerate(hex_str_list):
            if isinstance(item, list):
                hex_str_list[index] = ContractDataParser.to_b58_address_list(item)
            elif isinstance(item, str):
                hex_str_list[index] = ContractDataParser.to_b58_address(item)
            else:
                raise SDKException(ErrorCode.other_error('invalid data'))
        return hex_str_list

    @staticmethod
    def to_bytes_address(hex_address: str) -> bytes:
        try:
            bytes_address = bytes.fromhex(hex_address)
        except ValueError as e:
            raise SDKException(ErrorCode.other_error(e.args[0]))
        address = Address(bytes_address)
        return address.to_bytes()

    @staticmethod
    def to_bytes_address_list(hex_str_list: list) -> List[bytes]:
        for index, item in enumerate(hex_str_list):
            if isinstance(item, list):
                hex_str_list[index] = ContractDataParser.to_bytes_address_list(item)
            elif isinstance(item, str):
                hex_str_list[index] = ContractDataParser.to_bytes_address(item)
            else:
                raise SDKException(ErrorCode.other_error('invalid data'))
        return hex_str_list

    @staticmethod
    def to_dict(item_serialize: str) -> dict:
        stream = StreamManager.get_stream(bytearray.fromhex(item_serialize))
        reader = BinaryReader(stream)
        return ContractDataParser.__deserialize_stack_item(reader)

    @staticmethod
    def __deserialize_stack_item(reader: BinaryReader) -> dict or bytearray:
        param_type = reader.read_byte()
        if param_type == BuildParams.Type.bytearray_type.value:
            b = reader.read_var_bytes()
            return b
        elif param_type == BuildParams.Type.bool_type.value:
            return reader.read_bool()
        elif param_type == BuildParams.Type.int_type.value:
            b = reader.read_var_bytes()
            return ContractDataParser.__big_int_from_bytes(bytearray(b))
        elif param_type == BuildParams.Type.struct_type.value or param_type == BuildParams.Type.array_type.value:
            count = reader.read_var_int()
            item_list = list()
            for _ in range(count):
                item = ContractDataParser.__deserialize_stack_item(reader)
                item_list.append(item)
            if param_type == BuildParams.Type.struct_type.value:
                return Struct(item_list)
            return item_list
        elif param_type == BuildParams.Type.dict_type.value:
            count = reader.read_var_int()
            item_dict = dict()
            for _ in range(count):
                key = ContractDataParser.__deserialize_stack_item(reader)
                value = ContractDataParser.__deserialize_stack_item(reader)
                item_dict[key] = value
            return item_dict
        else:
            raise SDKException(ErrorCode.other_error('type error'))

    @staticmethod
    def __big_int_from_bytes(ba: bytearray):
        if len(ba) == 0:
            return 0
        ba_temp = ba[:]
        ba_temp.reverse()
        if ba_temp[0] >> 7 == 1:
            res = int.from_bytes(ba_temp, 'big', signed=True)
            return res
        return int.from_bytes(ba_temp, 'big', signed=True)

    @staticmethod
    def neo_bytearray_to_big_int(value: bytearray) -> int:
        if len(value) == 0:
            return 0
        ba_temp = value[:]
        ba_temp.reverse()
        if ba_temp[0] >> 7 == 1:
            res = int.from_bytes(ba_temp, 'big', signed=True)
            return res
        return int.from_bytes(ba_temp, 'big', signed=True)

    @staticmethod
    def big_int_to_neo_bytearray(data: int) -> bytearray:
        if data == 0:
            return bytearray()
        data_bytes = ContractDataParser.int_to_bytearray(data)
        if len(data_bytes) == 0:
            return bytearray()
        if data < 0:
            data_bytes2 = ContractDataParser.int_to_bytearray(-data)
            b = data_bytes2[0]
            data_bytes.reverse()
            if b >> 7 == 1:
                res = data_bytes[:] + bytearray([255])
                return res
            return data_bytes
        else:
            b = data_bytes[0]
            data_bytes.reverse()
            if b >> 7 == 1:
                res = data_bytes[:] + bytearray([0])
                return res
            return data_bytes

    @staticmethod
    def int_to_bytearray(data: int):
        bit_length = data.bit_length() // 8
        t = data.bit_length() / 8
        if bit_length <= t:
            bit_length += 1
        return bytearray(data.to_bytes(bit_length, "big", signed=True))

    @staticmethod
    def parse_addr_addr_int_notify(notify: dict):
        notify['States'][0] = ContractDataParser.to_utf8_str(notify['States'][0])
        notify['States'][1] = ContractDataParser.to_b58_address(notify['States'][1])
        notify['States'][2] = ContractDataParser.to_b58_address(notify['States'][2])
        notify['States'][3] = ContractDataParser.to_int(notify['States'][3])
        return notify

'''