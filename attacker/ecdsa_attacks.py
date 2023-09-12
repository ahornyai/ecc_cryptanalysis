from utils.signature import recover_public_key

from attacks.nonce_reuse import nonce_reuse_attack
from attacks.lattice_attacks.msb_attack import msb_attack
from attacks.lattice_attacks.lsb_attack import lsb_attack
from attacks.lattice_attacks.prefix_msb_attack import prefix_msb_attack
from attacks.lattice_attacks.prefix_lsb_attack import prefix_lsb_attack

attacks = [
    {
        "name": "Nonce reuse",
        "function": nonce_reuse_attack,
        "rounds": [
            {
                "signatures": "all"
            }
        ]
    },
    {
        "name": "Prefix MSB attack",
        "function": prefix_msb_attack,
        "rounds": [
            {
                "signatures": 7,
            },
            {
                "signatures": 10,
            },
            {
                "signatures": 19,
            },
            {
                "signatures": 37,
            },
        ]
    },
    {
        "name": "MSB attack",
        "function": msb_attack,
        "rounds": [ # these signatures can be lowered by maybe 2 or 3, but based on the unit tests, these should work for every case
            {
                "signatures": 6,
                "args": [128]
            },
            {
                "signatures": 8,
                "args": [96]
            },
            {
                "signatures": 9,
                "args": [64]
            },
            {
                "signatures": 18,
                "args": [32]
            },
            {
                "signatures": 36,
                "args": [16]
            },
        ]
    },
    {
        "name": "Prefix LSB attack",
        "function": prefix_lsb_attack,
        "rounds": [
            {
                "signatures": 7,
                "args": [128]
            },
            {
                "signatures": 10,
                "args": [64]
            },
            {
                "signatures": 19,
                "args": [32]
            },
            {
                "signatures": 41,
                "args": [16]
            },
        ]
    },
    {
        "name": "LSB attack",
        "function": lsb_attack,
        "rounds": [
            {
                "signatures": 6,
                "args": [128]
            },
            {
                "signatures": 8,
                "args": [96]
            },
            {
                "signatures": 9,
                "args": [64]
            },
            {
                "signatures": 18,
                "args": [32]
            },
            {
                "signatures": 40,
                "args": [16]
            },
        ]
    }
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
        print("Public key recovered: {}".format(pubkey))
    
    print("Step 2: Starting the attacks...")
    for attack in attacks:
        print("Starting attack: {}".format(attack["name"]))

        for attack_round in attack["rounds"]:
            if attack_round["signatures"] == "all":
                signatures_count = len(signatures["r"])
            else:
                signatures_count = attack_round["signatures"]
            
            if len(signatures["r"]) < signatures_count:
                print("Not enough signatures to perform the attack, skipping...")
                continue

            args = attack_round["args"] if "args" in attack_round else []
            round_signatures = {
                "r": signatures["r"][:signatures_count],
                "s": signatures["s"][:signatures_count],
                "h": signatures["h"][:signatures_count],
                "kp": signatures["kp"][:signatures_count] if "kp" in signatures else []
            }
            
            print("Analysing {} signatures with args: {}".format(signatures_count, args))
            d = attack["function"](round_signatures, pubkey, curve, generator, *args)

            if d != None:
                print("Private key recovered: {}".format(hex(d)))
                return

