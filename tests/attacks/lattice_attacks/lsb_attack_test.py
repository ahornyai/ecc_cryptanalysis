import unittest

from attacks.lattice_attacks.lsb_attack import LSBAttack
from utils.signature import sign
from utils.curves import sec256r1, gen_sec256r1
from hashlib import sha1, sha256
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random

attacker = LSBAttack()

class TestLSBAttack(unittest.TestCase):
    def test_lsb_attack_96(self):
        # We use sha1 as the hash function and we bitshift it to the left, so we know that the last 96 bits are 0
        signatures = {
            "r": [],
            "s": [],
            "h": [],
            "kp": []
        }
        d = random.randint(1, sec256r1.order() - 1)

        for i in range(6):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha1(message).digest()
            nonce = sha1(long_to_bytes(d) + h).digest()

            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, hash=sha1, k=bytes_to_long(nonce) << 96)

            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))
            signatures["kp"].append(0)

        assert attacker.attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1) == d
    
    def test_lsb_attack_128(self):
        # In this case we will have a 128 bit leak of the 256 bit nonce (LSB)
        signatures = {
            "r": [],
            "s": [],
            "h": [],
            "kp": []
        }

        d = random.randint(1, sec256r1.order() - 1)

        for i in range(6):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha256(message).digest()
            nonce = bytes_to_long(sha256(long_to_bytes(d) + h).digest())

            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, k=nonce)

            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))
            signatures["kp"].append(nonce & ((1 << 128) - 1))

        assert attacker.attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1) == d
    
    def test_lsb_attack_64(self):
        signatures = {
            "r": [],
            "s": [],
            "h": [],
            "kp": []
        }

        d = random.randint(1, sec256r1.order() - 1)

        for i in range(9):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha256(message).digest()
            nonce = bytes_to_long(sha256(long_to_bytes(d) + h).digest())

            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, k=nonce)

            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))
            signatures["kp"].append(nonce & ((1 << 64) - 1))

        assert attacker.attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1) == d
    
    def test_lsb_attack_32(self):
        signatures = {
            "r": [],
            "s": [],
            "h": [],
            "kp": []
        }

        d = random.randint(1, sec256r1.order() - 1)

        for i in range(18):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha256(message).digest()
            nonce = bytes_to_long(sha256(long_to_bytes(d) + h).digest())

            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, k=nonce)

            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))
            signatures["kp"].append(nonce & ((1 << 32) - 1))

        assert attacker.attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1) == d
    
    def test_lsb_attack_16(self):
        signatures = {
            "r": [],
            "s": [],
            "h": [],
            "kp": []
        }

        d = random.randint(1, sec256r1.order() - 1)

        for i in range(40):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha256(message).digest()
            nonce = bytes_to_long(sha256(long_to_bytes(d) + h).digest())

            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, k=nonce)

            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))
            signatures["kp"].append(nonce & ((1 << 16) - 1))

        assert attacker.attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1) == d