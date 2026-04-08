from core.group_params import P, G, H


def pedersen_commit(s: int, r: int) -> int:
    return (pow(G, s, P) * pow(H, r, P)) % P


def verify_commitment(commitment: int, s: int, r: int) -> bool:
    expected = pedersen_commit(s, r)
    return commitment == expected