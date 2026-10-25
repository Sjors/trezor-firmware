# flake8: noqa: F403,F405
from common import *  # isort:skip
from trezor.enums import InputScriptType
from trezor.messages import TxInput
from trezor.wire import DataError

from apps.bitcoin.scripts import write_witness_p2tr
from apps.bitcoin.sign_tx.helpers import _sanitize_tx_input
from apps.bitcoin.sign_tx.tx_weight import TxWeightCalculator
from apps.common import coins


def make_input(**fields):
    return TxInput(
        address_n=[0x80000056, 0x80000001, 0x80000000, 0, 0],
        prev_hash=bytes(32),
        prev_index=0,
        amount=100000,
        script_type=InputScriptType.SPENDTAPROOT,
        **fields,
    )


class TestAntiExfilInputs(unittest.TestCase):
    def test_ordinary_input(self):
        txi = make_input()
        self.assertIsNone(txi.anti_exfil_host_commitment)
        self.assertIsNone(txi.anti_exfil_sighash)
        self.assertIs(_sanitize_tx_input(txi, coins.by_name("Testnet")), txi)

    def test_valid_rounds(self):
        for sighash in (None, 0, 1):
            txi = make_input(
                anti_exfil_host_commitment=bytes(32), anti_exfil_sighash=sighash
            )
            self.assertIs(_sanitize_tx_input(txi, coins.by_name("Testnet")), txi)
            txi.anti_exfil_signer_nonce = bytes([2]) + bytes(32)
            txi.anti_exfil_host_entropy = bytes(32)
            self.assertIs(_sanitize_tx_input(txi, coins.by_name("Testnet")), txi)

    def test_sighash_weight_matches_witness(self):
        for sighash in (0, 1):
            txi = make_input(
                anti_exfil_host_commitment=bytes(32), anti_exfil_sighash=sighash
            )
            witness = bytearray()
            write_witness_p2tr(witness, bytes(64), sighash)
            # input_script_size excludes the witness item-count prefix.
            self.assertEqual(
                TxWeightCalculator.input_script_size(txi), len(witness) - 1
            )

    def test_partial_and_malformed_transcripts(self):
        for fields in (
            {"anti_exfil_sighash": 0},
            {"anti_exfil_signer_nonce": bytes(33)},
            {"anti_exfil_host_entropy": bytes(32)},
            {"anti_exfil_host_commitment": bytes(31)},
            {"anti_exfil_host_commitment": bytes(32), "anti_exfil_sighash": 2},
            {
                "anti_exfil_host_commitment": bytes(32),
                "anti_exfil_signer_nonce": bytes(33),
            },
            {
                "anti_exfil_host_commitment": bytes(32),
                "anti_exfil_host_entropy": bytes(32),
            },
            {
                "anti_exfil_host_commitment": bytes(32),
                "anti_exfil_signer_nonce": bytes(32),
                "anti_exfil_host_entropy": bytes(32),
            },
        ):
            with self.assertRaises(DataError):
                _sanitize_tx_input(make_input(**fields), coins.by_name("Testnet"))


if __name__ == "__main__":
    unittest.main()
