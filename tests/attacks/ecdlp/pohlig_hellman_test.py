import unittest

from sage.all import EllipticCurve, GF
from attacks.ecdlp.pohlig_hellman import PohligHellmanAttack
from utils.signature import sign
from utils.curves import sec256r1, gen_sec256r1
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
import random

attacker = PohligHellmanAttack()

class PohligHellmanTest(unittest.TestCase):
    def test_pohlig_hellman(self):
        E = EllipticCurve(GF(17101937747109687265202713197737423), [2, 3]) # define a smooth curve
        d = random.randint(1, E.order() - 1)
        G = E.gens()[0]
        
        assert attacker.attack(G*d, E, G) == d
