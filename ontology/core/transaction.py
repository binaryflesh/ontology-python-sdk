from ontology.common.serialize import write_byte, write_uint32, write_uint64, write_var_uint
from ontology.crypto.Digest import Digest
from ontology.io.BinaryWriter import BinaryWriter
from ontology.io.MemoryStream import StreamManager
from ontology.utils.util import bytes_reader

class Transaction(object):
    def __init__(self, version, tx_type, nonce, gas_price, gas_limit, payer, payload, attributes, sigs, hash):
        self.version = version
        self.tx_type = tx_type
        self.nonce = nonce
        self.gas_price = gas_price
        self.gas_limit = gas_limit
        self.payer = payer  # common.address [20]bytes
        self.payload = payload
        self.attributes = attributes
        self.sigs = sigs  # Sig class array
        self.hash = hash  # [32]byte

    def serialize_unsigned(self):
        ms = StreamManager.GetStream()
        writer = BinaryWriter(ms)
        writer.WriteUInt8(self.version)
        writer.WriteUInt8(self.tx_type)
        writer.WriteUInt32(self.nonce)
        writer.WriteUInt64(self.gas_price)
        writer.WriteUInt64(self.gas_limit)
        writer.WriteBytes(bytes(self.payer))
        writer.WriteBytes(bytes(self.payload))
        writer.WriteVarInt(len(self.attributes))
        ms.flush()
        res = ms.ToArray()
        StreamManager.ReleaseStream(ms)
        return res

    def hash256(self):
        tx_serial = self.serialize_unsigned()
        tx_serial = bytes_reader(tx_serial)
        r = Digest.hash256(tx_serial)
        r = Digest.hash256(r)
        return r

    def serialize(self):


        '''
        func (tx *Transaction) Serialize(w io.Writer) error {

	err := tx.SerializeUnsigned(w)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "[Serialize], Transaction txSerializeUnsigned Serialize failed.")
	}

	err = serialization.WriteVarUint(w, uint64(len(tx.Sigs)))
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "[Serialize], Transaction serialize tx sigs length failed.")
	}
	for _, sig := range tx.Sigs {
		err = sig.Serialize(w)
		if err != nil {
			return err
		}
	}

	return nil
        :return:
        '''


class Sig(object):
    def __init__(self, public_keys, M, sig_data):
        self.public_keys = []  # a list to save public keys
        self.M = 0
        self.sig_data = []  # [][]byte
