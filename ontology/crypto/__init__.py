import threading

from typing import List

from ontology.crypto.digest import Digest
from ontology.exception import SDKException, ErrorCode
from ontology.utils.contract_data import ContractDataParser

"""
TODO: copy paste documentation
"""


def str_to_bytes(s: str) -> bytes:
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode('latin-1')
    else:
        return bytes(list(s))


class MerkleVerifier(object):
    @staticmethod
    def get_proof(tx_block_height: int, target_hash_list: List[str], current_block_height: int):
        proof_node = list()
        last_node = current_block_height
        pos = 0
        while last_node > 0:
            if tx_block_height % 2 == 1:
                dict_node = dict(Direction='Left', TargetHash=target_hash_list[pos])
                proof_node.append(dict_node)
                pos += 1
            elif tx_block_height < last_node:
                dict_node = dict(Direction='Right', TargetHash=target_hash_list[pos])
                proof_node.append(dict_node)
                pos += 1
            tx_block_height //= 2
            last_node //= 2
        return proof_node

    @staticmethod
    def validate_proof(proof: List[dict], hex_target_hash: str, hex_merkle_root: str, is_big_endian: bool = False):
        if is_big_endian:
            hex_merkle_root = ContractDataParser.to_reserve_hex_str(hex_merkle_root)
            hex_target_hash = ContractDataParser.to_reserve_hex_str(hex_target_hash)
        if len(proof) == 0:
            return hex_target_hash == hex_merkle_root
        else:
            hex_proof_hash = hex_target_hash
            for node in proof:
                if is_big_endian:
                    sibling = ContractDataParser.to_reserve_hex_str(node['TargetHash'])
                else:
                    sibling = node['TargetHash']
                try:
                    direction = node['Direction'].lower()
                except KeyError:
                    raise SDKException(ErrorCode.other_error('Invalid proof'))
                if direction == 'left':
                    value = bytes.fromhex('01' + sibling + hex_proof_hash)
                    hex_proof_hash = Digest.sha256(value, is_hex=True)
                elif direction == 'right':
                    value = bytes.fromhex('01' + hex_proof_hash + sibling)
                    hex_proof_hash = Digest.sha256(value, is_hex=True)
                else:
                    raise SDKException(ErrorCode.other_error('Invalid proof.'))
            return hex_proof_hash == hex_merkle_root


class TxVerifier(object):
    _instance_lock = threading.Lock()

    def __init__(self, sdk):
        self.__sdk = sdk

    def __new__(cls, *args, **kwargs):
        if not hasattr(TxVerifier, '_instance'):
            with TxVerifier._instance_lock:
                if not hasattr(TxVerifier, '_instance'):
                    TxVerifier._instance = object.__new__(cls)
        return TxVerifier._instance

    def verify_by_tx_hash(self, tx_hash: str):
        merkle_proof = self.__sdk.get_network().get_merkle_proof(tx_hash)
        tx_block_height = merkle_proof['BlockHeight']
        current_block_height = merkle_proof['CurBlockHeight']
        target_hash_list = merkle_proof['TargetHashes']
        target_hash = merkle_proof['TransactionsRoot']
        merkle_root = merkle_proof['CurBlockRoot']
        proof_node = MerkleVerifier.get_proof(tx_block_height, target_hash_list, current_block_height)
        result = MerkleVerifier.validate_proof(proof_node, target_hash, merkle_root, True)
        return result
