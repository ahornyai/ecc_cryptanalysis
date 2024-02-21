from sage.all import factor, crt
from attacks.attack import ECDLPAttack

class PohligHellmanAttack(ECDLPAttack):

    def __init__(self):
        self.threshold = 50 # Only prime factors below 40 bits are considered

    def __str__(self):
        return f"Pohlig-Hellman algorithm"
    
    def attack(self, public_key, curve, G) -> int | None:
        q = G.order()
        primes = factor(q)
        moduli = []
        dlogs = []

        for a in primes:
            fac = a[0] ** a[1]
            
            if fac.bit_length() > self.threshold:
                continue

            t = int(q) // int(fac)
            dlog = (t*G).discrete_log(t*public_key)
            dlogs += [dlog]
            moduli += [fac]

        d = crt(dlogs, moduli)

        if d*G == public_key:
            return d
        
        return None
