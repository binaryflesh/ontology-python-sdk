import typing

from crypto.digest import Digest
from ontology import SDKException, ErrorCode
from utils.contract_data import ContractDataParser


def get_proof_node(tx_block_height: int, target_hash_list: typing.List[str], current_block_height: int):
    """
    locate proof node
    :param tx_block_height:
    :type tx_block_height:
    :param target_hash_list:
    :type target_hash_list:
    :param current_block_height:
    :type current_block_height:
    :return:
    :rtype:
    """
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


def verify_proof(proof: typing.List[dict], hex_target_hash: str, hex_merkle_root: str, is_big_endian=False):
    """
    Verify proof-of-stake
    :param proof:
    :type proof:
    :param hex_target_hash:
    :type hex_target_hash:
    :param hex_merkle_root:
    :type hex_merkle_root:
    :param is_big_endian:
    :type is_big_endian:
    :return:
    :rtype:
    """
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
