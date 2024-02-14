import unittest

from attacks.lattice_attacks.prefix_lsb_attack import PrefixLSBAttack
from utils.signature import sign
from utils.curves import sec256r1, gen_sec256r1
from hashlib import sha1, sha256
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random

class TestPrefixLSBAttack(unittest.TestCase):

    def test_prefix_msb_attack_128(self):
        signatures = {
            "r": [],
            "s": [],
            "h": [],
            "kp_bits": 128
        }

        d = random.randint(1, sec256r1.order() - 1)
        c = random.randint(0, 2**128)

        for i in range(8):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha256(message).digest()
            nonce = bytes_to_long(sha256(long_to_bytes(d) + h).digest())
            nonce = ((nonce << 128) + c) % 2**256 # make the last bits shared
            
            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, k=nonce)
            
            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))

        attacker = PrefixLSBAttack()

        assert attacker.attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1) == d
    