import argparse
import json
import time

from sage.all import EllipticCurve, GF
from utils.curves import from_str
from attacker.ecdsa_attacks import attack_ecdsa

def parse_file_ecdsa(file_name):
    print("Parsing file: {}, method: ECDSA".format(file_name))

    f = open(file_name, "r")

    data = json.load(f)

    if "signatures" not in data:
        print("No signatures found")
        exit(1)
    
    if "curve" not in data:
        print("No curve found")
        exit(1)
    
    signatures = data["signatures"]
    curve_json = data["curve"]

    if isinstance(curve_json, str):
        (curve, generator) = from_str(curve_json)
    else:
        curve = EllipticCurve(GF(curve_json["prime"]), curve_json["coefficients"])

        if "generator" in curve_json:
            generator = curve(curve_json["generator"][0], curve_json["generator"][1])
        else:
            generator = curve.gens()[0]
    
    if "r" not in signatures or "s" not in signatures or "h" not in signatures:
        print("Invalid signature format, example in README.md")
        exit(1)
    
    if len(signatures["r"]) != len(signatures["s"]) or len(signatures["r"]) != len(signatures["h"]) or len(signatures["s"]) != len(signatures["h"]):
        print("Length mismatch between r, s and h, check your input file")
        exit(1)

    if len(signatures["r"]) < 2:
        print("I need at least 2 signatures to perform the attacks")
        exit(1)
    
    print("Parsed {} signatures".format(len(signatures["r"])))

    return (signatures, curve, generator)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Input file in JSON format", required=True)
    parser.add_argument("-s", "--ecdsa", help="Launch the script in ECDSA mode", default=False, action="store_true")
    parser.add_argument("-d", "--dlp", help="Launch the script in DLP mode", default=False, action="store_true")
    args = parser.parse_args()

    if args.ecdsa:
        (signatures, curve, generator) = parse_file_ecdsa(args.input)

        print("Curve: {}".format(curve))
        print("Generator: {}".format(generator))

        start_time = time.time()
        attack_ecdsa(signatures, curve, generator)
        print("Attack completed in {} seconds".format(round(time.time() - start_time, 2)))

        exit(1)
    
    if args.dlp:
        print("DLP mode not implemented yet")
        exit(1)
    
    print("Please specify a mode, -h for help")
    