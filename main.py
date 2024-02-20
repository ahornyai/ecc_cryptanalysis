import argparse
import time

from utils.parser import parse_file_ecdlp, parse_file_ecdsa
from attacker.ecdsa_attacks import attack_ecdsa
from attacker.ecdlp_attacks import attack_ecdlp

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Input file in JSON format", required=True)
    parser.add_argument("-s", "--ecdsa", help="Launch the script in ECDSA mode", default=False, action="store_true")
    parser.add_argument("-d", "--ecdlp", help="Launch the script in ECDLP mode", default=False, action="store_true")
    args = parser.parse_args()

    if args.ecdsa:
        (signatures, curve, generator) = parse_file_ecdsa(args.input)

        print(f"Curve: {curve}")
        print(f"Generator: {generator}")

        start_time = time.time()
        attack_ecdsa(signatures, curve, generator)
        print(f"Attack completed in {round(time.time() - start_time, 2)} seconds")

        exit(1)
    
    if args.dlp:
        (public_key, curve, generator) = parse_file_ecdlp(args.input)

        print(f"Curve: {curve}")
        print(f"Generator: {generator}")
        print(f"Public key: {public_key}")

        start_time = time.time()
        attack_ecdlp(public_key, curve, generator)
        print(f"Attack completed in {round(time.time() - start_time, 2)} seconds")

        exit(1)
    
    print("Please specify a mode, -h for help")
    