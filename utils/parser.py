from sage.all import EllipticCurve, GF
from utils.curves import from_str
import json

def parse_curve(curve_json):
    if isinstance(curve_json, str):
        (curve, generator) = from_str(curve_json)
    else:
        curve = EllipticCurve(GF(curve_json["prime"]), curve_json["coefficients"])

        if "generator" in curve_json:
            generator = curve(curve_json["generator"][0], curve_json["generator"][1])
        else:
            generator = curve.gens()[0]
    
    return curve, generator

def parse_file_ecdlp(file_name):
    print(f"Parsing file: {file_name}, method: ECDLP")

    f = open(file_name, "r")
    data = json.load(f)

    if "curve" not in data:
        print("No curve found")
        exit(1)
    
    if "public_key" not in data:
        print("No public key found")
        exit(1)
    
    (curve, generator) = parse_curve(data["curve"])
    public_key = curve(data["public_key"])

    return (public_key, curve, generator)
    

def parse_file_ecdsa(file_name):
    print(f"Parsing file: {file_name}, method: ECDSA")

    f = open(file_name, "r")
    data = json.load(f)

    if "signatures" not in data:
        print("No signatures found")
        exit(1)
    
    if "curve" not in data:
        print("No curve found")
        exit(1)
    
    signatures = data["signatures"]
    (curve, generator) = parse_curve(data["curve"])
    
    if "r" not in signatures or "s" not in signatures or "h" not in signatures:
        print("Invalid signature format, example in README.md")
        exit(1)
    
    if len(signatures["r"]) != len(signatures["s"]) or len(signatures["r"]) != len(signatures["h"]) or len(signatures["s"]) != len(signatures["h"]):
        print("Length mismatch between r, s and h, check your input file")
        exit(1)

    if len(signatures["r"]) < 2:
        print("I need at least 2 signatures to perform the attacks")
        exit(1)

    # Set default value to kp
    if "kp" not in signatures or len(signatures["kp"]) == 0:
        signatures["kp"] = [0] * len(signatures["r"])
    
    if "kp_bits" not in signatures:
        # This is just a good guess, the best if you specify the exact number in the input
        kp_length = 0

        for kp in signatures["kp"]:
            kp_length += kp.bit_length()
        
        signatures["kp_bits"] = kp_length // len(signatures["kp"]) + 1
    
    print(f"Parsed {len(signatures['r'])} signatures")

    return (signatures, curve, generator)