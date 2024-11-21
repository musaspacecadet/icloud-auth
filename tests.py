import unittest
import asyncio
from srp import Srp, Mode, Hash  # Assuming you have a Python equivalent `srp` module
from utils import from_hex, bigint_from_bytes, bytes_from_bigint, constant_time_compare  # Utility functions
from binascii import hexlify

class TestSrpTools(unittest.IsolatedAsyncioTestCase):
    def test_client_srp_tools(self):
        # Test vectors from the given test vectors JSON file.
        test = {
            "I": b"alice",
            "P": b"password123",
            "s": from_hex("beb25379d1a8581eb5a727673a2441ee"),
            "v": from_hex("7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb"),
            "a": from_hex("60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393"),
            "A": from_hex("61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b"),
            "B": from_hex("bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58"),
            "K": from_hex("017eefa1cefc5c2e626e21598987f31e0f1b11bb"),
            "M1": from_hex("3f3bc67169ea71302599cf1b0f5d408b7b65d347"),
        }

        srp = Srp(Mode.SRPTools, Hash.SHA1, 1024)

        # Verifier test
        verifier = srp.verifier(test["I"], test["P"], test["s"])
        self.assertTrue(
            constant_time_compare(verifier.v, test["v"]),
            f"Verifier mismatch; expected {test['v']}, got {verifier.v}"
        )

        # Client test
        client = srp.new_client(test["I"], test["P"], bigint_from_bytes(test["a"]))
        self.assertTrue(
            constant_time_compare(bytes_from_bigint(client.A), test["A"]),
            f"A value mismatch; expected {test['A']}, got {bytes_from_bigint(client.A)}"
        )

        # Generate M1 and verify
        M1 = client.generate(test["s"], test["B"])
        self.assertTrue(
            constant_time_compare(from_hex(M1), test["M1"]),
            f"M1 mismatch; expected {test['M1']}, got {from_hex(M1)}"
        )

        # Verify shared key
        self.assertTrue(
            constant_time_compare(client.K, test["K"]),
            f"Shared key mismatch; expected {test['K']}, got {client.K}"
        )

if __name__ == "__main__":
    asyncio.run(unittest.main())
