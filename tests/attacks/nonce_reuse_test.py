import unittest

from attacks.nonce_reuse import nonce_reuse_attack
from utils.signature import sign
from utils.curves import sec256r1, gen_sec256r1
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
import random

class TestNonceReuse(unittest.TestCase):
    def test_nonce_reuse(self):
        message1 = b"Hello, world!"
        message2 = b"This is a different message!"
        message3 = b"This is another different message!"

        d = random.randint(1, sec256r1.order() - 1)

        (r1, s1) = sign(d, message1, sec256r1, G=gen_sec256r1, k=0xcafebabe)
        (r2, s2) = sign(d, message2, sec256r1, G=gen_sec256r1)
        (r3, s3) = sign(d, message3, sec256r1, G=gen_sec256r1, k=0xcafebabe)

        signatures = {
            "r": [r1, r2, r3],
            "s": [s1, s2, s3],
            "h": [bytes_to_long(sha256(message1).digest()), bytes_to_long(sha256(message2).digest()), bytes_to_long(sha256(message3).digest())]
        }

        assert nonce_reuse_attack(signatures, None, sec256r1, None) == d
