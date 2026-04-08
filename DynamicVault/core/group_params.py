import hashlib

P = 156240993757110356204834766109868060734460775393383264579156100434103528556667
Q = 78120496878555178102417383054934030367230387696691632289578050217051764278333

G = pow(2, 2, P)


def derive_h():
    seed = hashlib.sha256(
        b"pedersen_vss_h_generator_nothing_up_my_sleeve"
    ).digest()

    h_candidate = int.from_bytes(seed, "big") % P
    h = pow(h_candidate, (P - 1) // Q, P)

    return h


H = derive_h()