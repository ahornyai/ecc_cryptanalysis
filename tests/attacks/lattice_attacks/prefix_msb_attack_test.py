import unittest

from attacks.lattice_attacks.prefix_msb_attack import prefix_msb_attack
from utils.signature import sign
from utils.curves import sec256r1, gen_sec256r1
from hashlib import sha1, sha256
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random

class TestPrefixMSBAttack(unittest.TestCase):

    def test_prefix_msb_attack_128(self):
        signatures = {
            "r": [],
            "s": [],
            "h": []
        }

        d = random.randint(1, sec256r1.order() - 1)
        c = random.randint(0, 2**128)

        for i in range(8):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha256(message).digest()
            nonce = bytes_to_long(sha1(long_to_bytes(d) + h).digest())
            nonce = nonce | c << 128

            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, k=nonce)
            
            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))

        assert prefix_msb_attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1) == d
    
    def test_prefix_msb_attack_96(self):
        signatures = {
            "r": [],
            "s": [],
            "h": []
        }

        d = random.randint(1, sec256r1.order() - 1)
        c = random.randint(0, 2**96)

        for i in range(8):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha256(message).digest()
            nonce = bytes_to_long(sha1(long_to_bytes(d) + h).digest())
            # set the first 96 bits to a constant
            nonce = nonce | c << 160 

            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, k=nonce)
            
            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))
        
        assert prefix_msb_attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1) == d
    
    def test_prefix_msb_attack_64(self):
        signatures = {
            "r": [],
            "s": [],
            "h": []
        }

        d = random.randint(1, sec256r1.order() - 1)
        c = random.randint(0, 2**64)

        for i in range(12):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha256(message).digest()
            nonce = bytes_to_long(sha1(long_to_bytes(d) + h).digest())
            nonce = nonce | c << (192)

            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, k=nonce)
            
            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))

        assert prefix_msb_attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1) == d