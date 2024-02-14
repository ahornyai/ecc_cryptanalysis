from sage.all import vector, matrix
from sage.modules.free_module_integer import IntegerLattice
from attacks.attack import ECDSAttack

class PrefixMSBAttack(ECDSAttack):

    def __str__(self):
        return f"Prefix MSB attack"
    
    def attack(self, signatures, pubkey, curve, generator) -> int | None:
        # if we have shared most significant bits in the nonce, but we don't know those bits, we can use this attack
        order = curve.order()

        # One signature is used as an offset (so we can get rid of the unknown most significant bits of the nonce)
        offset_r = signatures["r"][0]
        offset_s = signatures["s"][0]
        offset_inv_s = pow(signatures["s"][0], -1, order)
        offset_h = signatures["h"][0]

        signatures["r"] = signatures["r"][1:]
        signatures["s"] = signatures["s"][1:]
        signatures["h"] = signatures["h"][1:]

        sample_size = len(signatures["r"])
        s_inverse = [pow(s, -1, order) for s in signatures["s"]]

        # We subtract the offset signature from the signatures
        A = vector([(s_inv * r - offset_inv_s * offset_r) % order for (s_inv, r) in zip(s_inverse, signatures["r"])])
        B = vector([(s_inv * h - offset_inv_s * offset_h) % order for (s_inv, h) in zip(s_inverse, signatures["h"])])

        m = matrix((matrix.identity(sample_size) * order).rows() + [A] + [B])

        lattice = IntegerLattice(m)
        k_prime = lattice.shortest_vector(preprocess=2, pruning=False) # preprocess=2 means run the LLL algorithm

        # k' = k_n - k_0
        # we know that k = s^-1 * (h + d * r) mod order
        # based on this we can solve for d
        privkeys = [(k * s * offset_s - offset_s * h + s * offset_h) * pow(r * offset_s - offset_r * s, -1, order) % order for r, s, h, k in zip(signatures["r"], signatures["s"], signatures["h"], k_prime)]

        for privkey in privkeys:
            if pubkey == privkey * generator:
                return privkey
        
        return None
