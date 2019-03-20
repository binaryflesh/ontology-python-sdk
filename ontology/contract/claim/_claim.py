import uuid
import time
import claim
import base64

from account import Account
from crypto.digest import Digest
from crypto.signature_handler import SignatureHandler

from ontology import SDKException, ErrorCode

from claim.proof import BlockchainProof
from claim.payload import Payload
from claim.header import Header
from claim.verify import VerifyTx


class Claim(object):

    def __init__(self, sdk):
        self.__sdk = sdk
        self.__head = None
        self.__payload = None
        self.__signature = b''
        self.__blk_proof = BlockchainProof(sdk)

    def __iter__(self):
        data = dict(Header=dict(self.__head), Payload=dict(self.__payload), Signature=self.to_str_signature(),
                    Proof=dict(self.__blk_proof))
        for key, value in data.items():
            yield (key, value)

    @property
    def claim_id(self):
        if self.__payload is None:
            return ''
        return self.__payload.jti

    @property
    def head(self):
        return self.__head

    @head.setter
    def head(self, kid: str):
        if not isinstance(kid, str):
            raise SDKException(ErrorCode.require_str_params)
        self.__head = claim.header.Header(kid)

    @property
    def payload(self):
        return self.__payload

    @property
    def signature(self):
        return self.__signature

    @property
    def blk_proof(self):
        return self.__blk_proof

    @blk_proof.setter
    def blk_proof(self, blk_proof: dict):
        self.__blk_proof.proof = blk_proof

    def set_claim(self, kid: str, iss_ont_id: str, sub_ont_id: str, exp: int, context: str, clm: dict, clm_rev: dict,
                  jti: str = '', ver: str = 'v1.0'):
        if not isinstance(jti, str):
            raise SDKException(ErrorCode.require_str_params)
        if jti == '':
            jti = Digest.sha256(uuid.uuid1().bytes, is_hex=True)
        self.__head = Header(kid)
        self.__payload = Payload(ver, iss_ont_id, sub_ont_id, int(time.time()), exp, context, clm, clm_rev, jti)

    def generate_signature(self, iss: Account, verify_kid: bool = True):
        if not isinstance(self.__head, Header) or not isinstance(self.__payload, Payload):
            raise SDKException(ErrorCode.other_error('Please set claim parameters first.'))
        if verify_kid:
            key_index = int(self.__head.kid.split('-')[1])
            result = self.__sdk.native_vm.ont_id().verify_signature(iss.get_ont_id(), key_index, iss)
            if not result:
                raise SDKException(ErrorCode.other_error('Issuer account error.'))
        b64_head = self.__head.to_base64()
        b64_payload = self.__payload.to_base64()
        msg = f'{b64_head}.{b64_payload}'.encode('utf-8')
        self.__signature = iss.generate_signature(msg)
        return self.__signature

    def validate_signature(self, b64_claim: str):
        try:
            b64_head, b64_payload, b64_signature, _ = b64_claim.split('.')
        except ValueError:
            raise SDKException(ErrorCode.invalid_b64_claim_data)
        head = Header.from_base64(b64_head)
        payload = Payload.from_base64(b64_payload)
        signature = base64.b64decode(b64_signature)
        kid = head.kid
        iss_ont_id = payload.iss
        msg = f'{b64_head}.{b64_payload}'.encode('ascii')
        pk = ''
        pub_keys = self.__sdk.native_vm.ont_id().get_public_keys(iss_ont_id)
        if len(pub_keys) == 0:
            raise SDKException(ErrorCode.invalid_claim_head_params)
        for pk_info in pub_keys:
            if kid == pk_info.get('PubKeyId', ''):
                pk = pk_info.get('Value', '')
                break
        if pk == '':
            raise SDKException(ErrorCode.invalid_b64_claim_data)
        handler = SignatureHandler(head.alg)
        result = handler.verify_signature(pk, msg, signature)
        return result

    def to_bytes_signature(self):
        return self.__signature

    def to_str_signature(self):
        return self.__signature.decode('latin-1')

    def to_b64_signature(self):
        return base64.b64encode(self.to_bytes_signature()).decode('ascii')

    @staticmethod
    def from_base64_signature(b64_signature: str):
        return bytes.hex(base64.b64decode(b64_signature))

    def generate_blk_proof(self, iss_acct: Account, payer: Account, gas_limit: int,
                           gas_price: int, is_big_endian=True, hex_contract_addr=''):
        while True:
            if isinstance(hex_contract_addr, str) and len(hex_contract_addr) == 40:
                continue
            self.__sdk.neo_vm.claim_record().hex_contract_address = hex_contract_addr
            tx = self.__sdk.neo_vm.claim_record()
            tx_hash = yield tx.commit(self.payload.jti, iss_acct, self.payload.sub, payer, gas_limit, gas_price)
            time.sleep(12)
            proof = VerifyTx(self.__sdk)
            hex_contract_addr = self.__sdk.neo_vm.claim_record().hex_contract_address
            merkle_proof = self.__sdk.get_network().get_merkle_proof(tx_hash)
            tx_block_height = merkle_proof['BlockHeight']
            current_block_height = merkle_proof['CurBlockHeight']
            target_hash = merkle_proof['TransactionsRoot']
            merkle_root = merkle_proof['CurBlockRoot']
            target_hash_list = merkle_proof['TargetHashes']
            proof_node = claim.verify.get_proof_node(tx_block_height, target_hash_list, current_block_height)
            if not claim.verify.verify_proof(proof_node, target_hash, merkle_root, is_big_endian):
                raise SDKException(ErrorCode.invalid_merkle_root)
            self.__blk_proof.set_proof(tx_hash, hex_contract_addr, tx_block_height, merkle_root, proof_node)
            return self.__blk_proof

    def validate_blk_proof(self, is_big_endian: bool = True):
        return self.__blk_proof.validate_blk_proof(is_big_endian)

    def to_base64(self):
        b64_head = self.__head.to_base64()
        b64_payload = self.__payload.to_base64()
        b64_signature = self.to_b64_signature()
        b64_blockchain_proof = self.__blk_proof.to_base64()
        return f'{b64_head}.{b64_payload}.{b64_signature}.{b64_blockchain_proof}'

    def from_base64(self, b64_claim: str, is_big_endian: bool = True):
        try:
            b64_head, b64_payload, b64_signature, b64_blk_proof = b64_claim.split('.')
        except ValueError:
            raise SDKException(ErrorCode.invalid_b64_claim_data)
        self.__head = Header.from_base64(b64_head)
        self.__payload = Payload.from_base64(b64_payload)
        self.__signature = base64.b64decode(b64_signature)
        self.__blk_proof = claim.proof.BlockchainProof(self.__sdk).from_base64(b64_blk_proof, is_big_endian)
