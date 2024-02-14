from utils.signature import recover_public_key

from attacks.nonce_reuse import NonceReuseAttack
from attacks.lattice_attacks.msb_attack import MSBAttack
from attacks.lattice_attacks.lsb_attack import LSBAttack
from attacks.lattice_attacks.prefix_msb_attack import PrefixMSBAttack
from attacks.lattice_attacks.prefix_lsb_attack import PrefixLSBAttack

attacks = [
    NonceReuseAttack(),
    MSBAttack(),
    LSBAttack(),
    PrefixMSBAttack(),
    PrefixLSBAttack(),
]

def attack_ecdsa(signatures, curve, generator):
    print("Step 1: Recovering public key from the first two signatures...")

    pubkey = recover_public_key((signatures["r"][0], signatures["s"][0], signatures["h"][0]), 
                                (signatures["r"][1], signatures["s"][1], signatures["h"][1]), 
                                curve, 
                                G=generator)

    if pubkey == None:
        print("Cannot recover public key, are you sure the signatures are valid and they were signed by the same private key?")
        exit(1)
    else:
        print(f"Public key recovered: {pubkey}")
    
    print("Step 2: Starting the attacks...")
    for attack in attacks:
        if len(signatures["r"]) < attack.required_signatures():
            print("Not enough signatures to perform the attack, skipping...")
            continue

        signatures_count = attack.max_signatures()

        round_signatures = {
            "r": signatures["r"][:signatures_count],
            "s": signatures["s"][:signatures_count],
            "h": signatures["h"][:signatures_count],
            "kp": signatures["kp"][:signatures_count] if "kp" in signatures else [],
            "kp_bits": signatures["kp_bits"]
        }
        
        print(f"Analysing {len(signatures['r'])} signatures with {attack}")
        d = attack.attack(round_signatures, pubkey, curve, generator)

        if d != None:
            print(f"Private key recovered: {hex(d)}")
            return

