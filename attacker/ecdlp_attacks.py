from attacks.ecdlp.pohlig_hellman import PohligHellmanAttack

attacks = [
    # todo: Pollard's rho, BSGS, MOV-attack, Frey-Ruck attack, Singular curve attack, Smart's attack, etc...
    PohligHellmanAttack()
]

def attack_ecdlp(public_key, curve, generator):
    print("Starting the attacks...")
    
    for attack in attacks:
        print(f"Analysing public key with {attack}")
        d = attack.attack(public_key, curve, generator)

        if d != None:
            print(f"Private key recovered: {hex(d)}")
            return

