#!/usr/bin/env python3

import unittest

from ontology.exception import ErrorCode, SDKException, SDKRuntimeException


class TestSDKException(unittest.TestCase):
    def test_sdk_exception(self):
        try:
            raise SDKException(ErrorCode.param_error)
        except SDKException as e:
            self.assertEqual('param error', e.args[1])

        try:
            raise SDKException(ErrorCode.asset_name_error)
        except SDKException as e:
            self.assertEqual('OntAsset Error, asset name error', e.args[1])

    def test_sdk_runtime_exception(self):
        try:
            raise SDKRuntimeException(ErrorCode.encrypted_pri_key_error)
        except SDKRuntimeException as e:
            self.assertEqual("Account Error, Prikey length error", e.args[1])

        try:
            raise SDKRuntimeException(ErrorCode.left_tree_full)
        except SDKRuntimeException as e:
            self.assertEqual("left tree always full", e.args[1])


if __name__ == '__main__':
    unittest.main()
