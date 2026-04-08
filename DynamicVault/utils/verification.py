import secrets
from core.group_params import P, Q
from core.commitment import pedersen_commit


def batch_verify_shares(shares, commitments):

    weights = [secrets.randbelow(Q) for _ in shares]

    lhs = 1

    for w, (pid, s_i, r_i) in zip(weights, shares):
        lhs_i = pedersen_commit(s_i, r_i)
        lhs = (lhs * pow(lhs_i, w, P)) % P

    rhs = 1

    for k, C_k in enumerate(commitments):

        exponent = 0

        for w, (pid, _, _) in zip(weights, shares):
            exponent = (exponent + w * pow(pid, k, Q)) % Q

        rhs = (rhs * pow(C_k, exponent, P)) % P

    valid = lhs == rhs

    invalid_ids = [] if valid else [pid for pid, _, _ in shares]

    return valid, invalid_ids