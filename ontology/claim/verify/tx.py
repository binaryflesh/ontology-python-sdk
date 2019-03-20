import typing
import threading

from .merkle import get_proof_node, verify_proof


class TxVerifier(object):
    _instance_lock = threading.Lock()
    _sdk = None

    def __init__(self, sdk: typing.Optional[typing.Any], tx_hash: typing.Optional[str] = None):
        try:
            if self._sdk is None:
                self._sdk = sdk
                assert self._sdk is not None, AttributeError
            if tx_hash is not None:
                while True:
                    self._instance_lock.acquire(True, 60)
                    merkle_proof = sdk.get_network().get_merkle_proof(tx_hash)
                    tx_block_height = merkle_proof['BlockHeight']
                    current_block_height = merkle_proof['CurBlockHeight']
                    target_hash_list = merkle_proof['TargetHashes']
                    target_hash = merkle_proof['TransactionsRoot']
                    merkle_root = merkle_proof['CurBlockRoot']
                    node = yield from get_proof_node(tx_block_height, target_hash_list, current_block_height)
                    if not self.verify(await node, target_hash, merkle_root, True):
                        break
                    self._instance_lock.release()
                    continue
        except (AttributeError, ValueError) as exc:
            raise exc
        finally:
            super().__init__(self._sdk)

    def __new__(cls, *args, **kwargs):
        if not hasattr(TxVerifier, '_instance'):
            with TxVerifier._instance_lock:
                if not hasattr(TxVerifier, '_instance'):
                    TxVerifier._instance = object.__new__(cls)
        return TxVerifier._instance

    @classmethod
    def verify_by_tx_hash(cls, tx_hash: str):
        """

        :param tx_hash:
        :type tx_hash:
        :return:
        :rtype:
        """
        yield from super().__init__(cls._sdk, tx_hash)
        return

    @staticmethod
    def tx_node(tx_blk_height, target_hashes, present_height):
        """

        :param tx_blk_height:
        :type tx_blk_height:
        :param target_hashes:
        :type target_hashes:
        :param present_height:
        :type present_height:
        :return:
        :rtype:
        """
        return get_proof_node(tx_blk_height, target_hashes, present_height)

    @classmethod
    def verify(cls, proof, target_hash, merkle_root, big_endian=False):
        """

        :param proof:
        :type proof:
        :param target_hash:
        :type target_hash:
        :param merkle_root:
        :type merkle_root:
        :param big_endian:
        :type big_endian:
        :return:
        :rtype:
        """
        return verify_proof(proof, target_hash, merkle_root, big_endian)
