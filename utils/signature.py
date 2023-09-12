from sage.all import EllipticCurve, Integer
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
import random


def sign(privkey: int, message: bytes, curve: EllipticCurve, G=None, hash=sha256, k=None,) -> (int, int):
    order = curve.order()

    if k == None:
        k = random.randint(1, order - 1)
    
    if G == None:
        G = curve.gens()[0]
    
    r = (k * G).xy()[0].lift() % order
    s = (pow(k, -1, order) * (bytes_to_long(hash(message).digest()) + privkey * r)) % order

    return (r, s)

def recover_public_keys(signature: (int, int, int), curve: EllipticCurve, G=None):
    (r, s, v) = signature

    if G == None:
        G = curve.gens()[0]
    
    order = curve.order()

    if not isinstance(r, Integer):
        r = Integer(r)

    R = curve.lift_x(r)
    R_1 = curve(R[0], -R[1])

    pub1 = pow(r, -1, order) * (s*R - v*G)
    pub2 = pow(r, -1, order) * (s*R_1 - v*G)

    return (pub1, pub2)

def recover_public_key(signature1: (int, int, int), signature2: (int, int, int), curve: EllipticCurve, G=None):
    (pub1, pub2) = recover_public_keys(signature1, curve, G)
    (pub3, pub4) = recover_public_keys(signature2, curve, G)

    # Not beautiful, but it works :)
    if pub1 == pub3:
        return pub1
    elif pub1 == pub4:
        return pub1
    elif pub2 == pub3:
        return pub2
    elif pub2 == pub4:
        return pub2
    
    return None