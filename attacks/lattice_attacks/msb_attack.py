from sage.all import vector, matrix
from sage.modules.free_module_integer import IntegerLattice
from attacks.attack import ECDSAttack

class MSBAttack(ECDSAttack):

    def __str__(self):
        return f"MSB attack"
    
    def attack(self, signatures, pubkey, curve, generator) -> int | None:
        order = curve.order()
        sample_size = len(signatures["r"])
        s_inverse = [pow(s, -1, order) for s in signatures["s"]]
        unknown_nonce_bits = curve.order().nbits() - signatures["kp_bits"]

        offset = 2**(unknown_nonce_bits-1)
        offset_vec = vector([offset] * sample_size)

        # Solving the HNP for ECDSA in this case is equivalent to solving the SVP for the lattice
        # Setting up the lattice basis matrix, because we want to find the shortest vector in the lattice
        # we remove the known MSB of the nonce 
        # -> we get a shorter vector than the average random vector in the lattice
        # -> the shortest nonzero vector will be the nonce vector (hopefully)
        A = vector([(s_inv * r) % order for (s_inv, r) in zip(s_inverse, signatures["r"])])
        B = vector([(s_inv * h - (kp << unknown_nonce_bits)) % order for (s_inv, h, kp) in zip(s_inverse, signatures["h"], signatures["kp"])])

        # We model the residue class with adding the modulo in different dimensions as basis vector
        # -> we can wrap around the residue class (because a+n congruent to a (mod n) by definition)
        # We need to do this because the SVP is not defined for residue classes by default
        m = matrix((matrix.identity(sample_size) * order).rows() + [A] + [B - offset_vec])

        lattice = IntegerLattice(m)
        shortest = lattice.shortest_vector(preprocess=2, pruning=False) + offset_vec # preprocess=2 means run the LLL algorithm
        sig_k = [(kp << unknown_nonce_bits) + k for (k, kp) in zip(shortest, signatures["kp"])]

        privkeys = [(s * k - h) * pow(r, -1, order) % order for r, s, h, k in zip(signatures["r"], signatures["s"], signatures["h"], sig_k)]
        
        # Verify our finding
        for privkey in privkeys:
            if pubkey == privkey * generator:
                return privkey
        
        return None
