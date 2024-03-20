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
  - Pohlig-Hellman attack

# Requirements
- sage
- unittest
- pycryptodome
- hashlib
- TODO: dockerized solution

# Usage
- ECDSA: `python3 main.py -s -i examples/ddc2022_hard.json`

# Unit tests:
- Run all unit tests: `python test.py`

# Mathematical background:
- Details written down in some of the scripts
- https://eprint.iacr.org/2023/032.pdf -> the best explanation that I've ever encountered about lattices
- https://eprint.iacr.org/2019/023.pdf -> awesome work, epic bitcoin blockchain cryptanalysis