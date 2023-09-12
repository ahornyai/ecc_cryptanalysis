import unittest

from utils.signature import sign, recover_public_keys, recover_public_key
from utils.curves import sec256r1, gen_sec256r1
from hashlib import sha256
from Crypto.Util.number import bytes_to_long

class TestSignature(unittest.TestCase):
    def test_sign_sec256r1(self):
        signature = sign(0xdeadbeef, b"Hello, world!", sec256r1, G=gen_sec256r1, k=0xcafebabe)
        
        assert signature == (24263658747825920832689732415784889605604064865712420923296275588511293850988, 8175080891180266778309758304828884683385066655592633393668896189840031657042)

    def test_recover_public_keys(self):
        (r, s) = sign(0xdeadbeef, b"Hello, world!", sec256r1, G=gen_sec256r1, k=0xcafebabe)
        (p1, p2) = recover_public_keys((r, s, bytes_to_long(sha256(b"Hello, world!").digest())), sec256r1, G=gen_sec256r1)
        
        assert (p1, p2) == (gen_sec256r1*0xdeadbeef, sec256r1(86787768082186234210549997735575189640444583642189273647146795777284322603095, 24689997839204367779098075890173642303403441664641460601909508616682869313877))

    def test_recover_public_key(self):
        (r1, s1) = sign(0xdeadbeef, b"Hello, world!", sec256r1, G=gen_sec256r1, k=0xcafebabe)
        (r2, s2) = sign(0xdeadbeef, b"A different message!", sec256r1, G=gen_sec256r1, k=0xdeadbeef)  
        
        h1 =  bytes_to_long(sha256(b"Hello, world!").digest())
        h2 =  bytes_to_long(sha256(b"A different message!").digest())

        pubkey = recover_public_key((r1, s1, h1), (r2, s2, h2), sec256r1, G=gen_sec256r1)

        assert pubkey == gen_sec256r1*0xdeadbeef
              
