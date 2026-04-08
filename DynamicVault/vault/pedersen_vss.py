import secrets
from typing import List, Tuple, Optional

from core.group_params import Q, P
from core.field_arithmetic import poly_eval, lagrange_interpolate
from core.commitment import pedersen_commit


class PedersenVSS:

    def __init__(self, secret: int, threshold: int, n_participants: int):

        self.secret = secret
        self.threshold = threshold
        self.n = n_participants

        self.f_coeffs = [secret] + [secrets.randbelow(Q) for _ in range(threshold)]
        self.r_coeffs = [secrets.randbelow(Q) for _ in range(threshold + 1)]

        self.commitments = [
            pedersen_commit(self.f_coeffs[k], self.r_coeffs[k])
            for k in range(threshold + 1)
        ]

    def generate_share(self, participant_id):

        s_i = poly_eval(self.f_coeffs, participant_id, Q)
        r_i = poly_eval(self.r_coeffs, participant_id, Q)

        return (participant_id, s_i, r_i)

    def generate_all_shares(self):

        return [self.generate_share(i) for i in range(1, self.n + 1)]

    def get_public_commitments(self):

        return self.commitments.copy()

    def verify_share(self, pid, s_i, r_i):

        lhs = pedersen_commit(s_i, r_i)

        rhs = 1

        for k, C_k in enumerate(self.commitments):

            rhs = (rhs * pow(C_k, pid ** k, P)) % P

        return lhs == rhs

    @staticmethod
    def verify_share_static(pid, s_i, r_i, commitments):
        from core.commitment import pedersen_commit
        from core.group_params import P

        lhs = pedersen_commit(s_i, r_i)

        rhs = 1
        for k, C_k in enumerate(commitments):
            rhs = (rhs * pow(C_k, pid ** k, P)) % P

        return lhs == rhs

    @staticmethod
    def reconstruct_secret(shares, commitments, threshold):

        needed = threshold + 1

        verified = []

        for pid, s_i, r_i in shares:

            lhs = pedersen_commit(s_i, r_i)

            rhs = 1

            for k, C_k in enumerate(commitments):

                rhs = (rhs * pow(C_k, pid ** k, P)) % P

            if lhs == rhs:

                verified.append((pid, s_i))

        if len(verified) < needed:

            print("Not enough valid shares")

            return None

        return lagrange_interpolate(verified[:needed], Q)