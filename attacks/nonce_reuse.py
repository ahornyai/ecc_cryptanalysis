def find_duplicates(signatures):
    for i in range(len(signatures["r"])):
        for j in range(len(signatures["r"])):
            if signatures["r"][i] == signatures["r"][j] and i != j:
                return (i, j)
    
    return False


def nonce_reuse_attack(signatures, pubkey, curve, generator):
    if len(set(signatures["r"])) == len(set(signatures["s"])):
        return None
    
    duplicates = find_duplicates(signatures)
    order = curve.order()

    if not duplicates:
        return None
    
    # s_1 = k^-1 * (h_1 + r*d) (mod n)
    # s_2 = k^-1 * (h_2 + r*d) (mod n)
    # k = s_1^-1 * (h_1 + r*d) (mod n)
    # s_2 = (s_1^-1 * (h_1 + r*d))^-1 * (h_2 + r*d) = s_1 * (h_1 + r*d)^-1 * (h_2 + r*d) (mod n)
    # s_2 * (h_1 + r*d) = s_1 * (h_2 + r*d) (mod n)
    # s_2*h_1 + r*d*s_2 = s_1*h_2 + r*d*s_1 (mod n)
    # s_2*h_1 - s_1*h_2 = d(r*s_1 - r*s_2) (mod n)
    # (s_2 * h_1 - s_1 * h_2) * (r*s_1 - r*s_2)^-1 = d (mod n)

    (i, j) = duplicates
    r, s, h = signatures["r"], signatures["s"], signatures["h"]

    return (s[j] * h[i] - s[i] * h[j]) * pow(r[i] * s[i] - r[j] * s[j], -1, order) % order
