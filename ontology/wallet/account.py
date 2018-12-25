#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ontology.exception.error_code import ErrorCode
from ontology.exception.exception import SDKException


class AccountData(object):
    def __init__(self, address: str = '', enc_alg: str = "aes-256-gcm", key: str = "", algorithm="ECDSA", salt="",
                 param: dict = None, label: str = "", public_key: str = "", sign_scheme: str = "SHA256withECDSA",
                 is_default: bool = True, lock: bool = False):
        if param is None:
            param = {"curve": "P-256"}
        self.b58_address = address
        self.algorithm = algorithm
        self.enc_alg = enc_alg
        self.is_default = is_default
        self.key = key
        self.__label = label
        self.lock = lock
        self.parameters = param
        self.salt = salt
        self.public_key = public_key
        self.signature_scheme = sign_scheme

    def __iter__(self):
        data = dict()
        data['address'] = self.b58_address
        data['algorithm'] = self.algorithm
        data['enc-alg'] = self.enc_alg
        data['isDefault'] = self.is_default
        data['key'] = self.key
        data['label'] = self.__label
        data['lock'] = self.lock
        data['parameters'] = self.parameters
        data['salt'] = self.salt
        data['publicKey'] = self.public_key
        data['signatureScheme'] = self.signature_scheme
        for key, value in data.items():
            yield (key, value)

    @property
    def label(self):
        return self.__label

    @label.setter
    def label(self, label: str):
        if not isinstance(label, str):
            raise SDKException(ErrorCode.other_error('Invalid label.'))
        self.__label = label

    def set_b58_address(self, b58_address):
        self.b58_address = b58_address

    def set_public_key(self, public_key):
        self.public_key = public_key

    def set_key(self, key):
        self.key = key

    def get_b58_address(self):
        return self.b58_address

    def get_public_key_bytes(self):
        return self.public_key

    def get_key(self):
        return self.key
