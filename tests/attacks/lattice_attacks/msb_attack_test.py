import unittest

from attacks.lattice_attacks.msb_attack import msb_attack
from utils.signature import sign
from utils.curves import sec256r1, gen_sec256r1
from hashlib import sha1, sha256
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random

class TestMSBAttack(unittest.TestCase):
    
    def test_msb_attack_128(self):
        # In this case we will have a 128 bit leak of the 256 bit nonce
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
            signatures["kp"].append(nonce >> 128)

        assert msb_attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1, 128) == d
    
    def test_msb_attack_96(self):
        # We use sha1 as the hash function, so we know that the first 96 most significant bits are 0
        signatures = {
            "r": [],
            "s": [],
            "h": []
        }
        d = random.randint(1, sec256r1.order() - 1)

        for i in range(6):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha1(message).digest()
            nonce = sha1(long_to_bytes(d) + h).digest()

            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, hash=sha1, k=bytes_to_long(nonce))

            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))

        assert msb_attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1, 96) == d

    def test_msb_attack_64(self):
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
            signatures["kp"].append(nonce >> 192) # 256 - 64

        assert msb_attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1, 64) == d
    
    def test_msb_attack_32(self):
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
            signatures["kp"].append(nonce >> 224) # 256 - 32

        assert msb_attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1, 32) == d

    def test_msb_attack_16(self):
        signatures = {
            "r": [],
            "s": [],
            "h": [],
            "kp": []
        }

        d = random.randint(1, sec256r1.order() - 1)

        for i in range(36):
            message = b"Hello! This is my message! Message number " + bytes([i])

            h = sha256(message).digest()
            nonce = bytes_to_long(sha256(long_to_bytes(d) + h).digest())

            (r, s) = sign(d, message, sec256r1, G=gen_sec256r1, k=nonce)

            signatures["r"].append(r)
            signatures["s"].append(s)
            signatures["h"].append(bytes_to_long(h))
            signatures["kp"].append(nonce >> 240) # 256 - 16

        assert msb_attack(signatures, d*gen_sec256r1, sec256r1, gen_sec256r1, 16) == d
    