# Automated cryptanalysis for encryptions and digital signature algorithms based on elliptic curves

Implemented attacks:
- **ECDSA**:
  - Lattice attacks:
    - Shared prefix nonces (we don't even have to know the prefix, because the script is smart enough to eliminate the unknown, but shared parts)
    - Shared suffix nonces
    - Known least significant bits (nonce leakage)
    - Known most significant bits
  - Nonce reuse attack (the classic PS3 mistake, common challenge)
- **DLP**:
  - TODO

# Requirements
- sage
- unittest
- pycryptodome
- hashlib

# Usage
In the case of ECDSA: `python main.py -s -i prefix_msb.json`

# Unit tests:
- Run all unit tests: `python test.py`
- Run specific unit test: `python -m unittest tests/attacks/lattice_attacks/msb_attack_test.py`

# Mathematical background:
- Details written down in some of the scripts
- https://eprint.iacr.org/2023/032.pdf -> the best explanation that I've ever encountered about lattices
- https://eprint.iacr.org/2019/023.pdf -> awesome work, epic bitcoin blockchain cryptanalysis