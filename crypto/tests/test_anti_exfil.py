"""Independent draft BIP-EXFIL vectors for the shared One/Core primitive.

Run after make -C crypto tests/libtrezor-crypto.so VALGRIND=0.
"""

import ctypes
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LIB = ctypes.CDLL(str(ROOT / "libtrezor-crypto.so"))
LIB.zkp_context_init()
COMMIT = LIB.zkp_bip340_anti_exfil_commit
SIGN = LIB.zkp_bip340_anti_exfil_sign
COMMIT.argtypes = [ctypes.c_char_p] * 4
SIGN.argtypes = [ctypes.c_char_p] * 6


class TestAntiExfil(unittest.TestCase):
    def test_vectors_and_corrupt_transcripts(self):
        for vector in json.loads((ROOT / "anti_exfil_vectors.json").read_text()):
            with self.subTest(index=vector["index"]):
                sk, msg, h, rho, nonce, signature = (
                    bytes.fromhex(vector[name])
                    for name in (
                        "secret_key",
                        "message",
                        "host_commitment",
                        "host_nonce",
                        "signer_nonce",
                        "signature",
                    )
                )
                out = ctypes.create_string_buffer(33)
                self.assertEqual(COMMIT(sk, msg, h, out), 0)
                self.assertEqual(out.raw[:33], nonce)
                signed = ctypes.create_string_buffer(64)
                self.assertEqual(SIGN(sk, msg, h, nonce, rho, signed), 0)
                self.assertEqual(signed.raw[:64], signature)
                args = [sk, msg, h, nonce, rho]
                for index in range(5):
                    bad = list(args)
                    bad[index] = bytes([bad[index][0] ^ 1]) + bad[index][1:]
                    self.assertNotEqual(SIGN(*bad, signed), 0)
                    self.assertEqual(signed.raw[:64], bytes(64))
                for rho_bad in (
                    bytes(32),
                    bytes.fromhex(
                        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
                    ),
                    bytes([255]) * 32,
                ):
                    self.assertNotEqual(SIGN(sk, msg, h, nonce, rho_bad, signed), 0)


if __name__ == "__main__":
    unittest.main()
