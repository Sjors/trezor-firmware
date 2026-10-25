# flake8: noqa: F403,F405
from common import *  # isort:skip

from trezor.enums import InputScriptType
from trezor.messages import TxInput

from apps.bitcoin import writers


class TestWriters(unittest.TestCase):
    def test_tx_input(self):
        inp = TxInput(
            address_n=[0],
            amount=390000,
            prev_hash=bytes.fromhex(
                "d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"
            ),
            prev_index=0,
            sequence=0xFFFFFFFF,
            script_sig=b"0123456789",
        )

        b = bytearray()
        writers.write_tx_input(b, inp, inp.script_sig)
        self.assertEqual(len(b), 32 + 4 + 1 + 10 + 4)

        for bad_prevhash in (b"", b"x", b"hello", b"x" * 33):
            inp.prev_hash = bad_prevhash
            self.assertRaises(
                AssertionError, writers.write_tx_input, b, inp, inp.script_sig
            )

    def test_tx_input_check(self):
        inp = TxInput(
            address_n=[0],
            amount=390000,
            prev_hash=bytes.fromhex(
                "d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"
            ),
            prev_index=0,
            script_type=InputScriptType.SPENDWITNESS,
            sequence=0xFFFFFFFF,
            script_pubkey=bytes.fromhex(
                "76a91424a56db43cf6f2b02e838ea493f95d8d6047423188ac"
            ),
            script_sig=b"0123456789",
        )

        b = bytearray()
        writers.write_tx_input_check(b, inp)
        # Empty AE byte strings add three prefixes, followed by the uint32 sighash.
        self.assertEqual(
            len(b), 4 + 4 + 32 + 4 + 11 + 4 + 4 + 1 + 8 + 1 + 1 + 1 + 4 + 26 + 7
        )
        self.assertEqual(b[-7:], bytes(7))

        for bad_prevhash in (b"", b"x", b"hello", b"x" * 33):
            inp.prev_hash = bad_prevhash
            self.assertRaises(AssertionError, writers.write_tx_input_check, b, inp)

    def test_tx_input_check_binds_anti_exfil(self):
        inp = TxInput(
            amount=390000,
            prev_hash=bytes(32),
            prev_index=0,
            script_type=InputScriptType.SPENDTAPROOT,
            anti_exfil_host_commitment=bytes([1]) * 32,
            anti_exfil_signer_nonce=bytes.fromhex(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ),
            anti_exfil_host_entropy=bytes([2]) * 32,
            anti_exfil_sighash=0,
        )
        original = bytearray()
        writers.write_tx_input_check(original, inp)
        for field, value in (
            ("anti_exfil_host_commitment", bytes([3]) * 32),
            # Changing only the full nonce point's parity must change the check.
            ("anti_exfil_signer_nonce", bytes([3]) + inp.anti_exfil_signer_nonce[1:]),
            ("anti_exfil_host_entropy", bytes([4]) * 32),
            ("anti_exfil_sighash", 1),
        ):
            old_value = getattr(inp, field)
            setattr(inp, field, value)
            changed = bytearray()
            writers.write_tx_input_check(changed, inp)
            self.assertNotEqual(changed, original)
            setattr(inp, field, old_value)


if __name__ == "__main__":
    unittest.main()
