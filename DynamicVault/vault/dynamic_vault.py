"""
vault/dynamic_vault.py
──────────────────────
Dynamic Threshold Vault — extends Pedersen VSS with threshold adjustment.

Key idea:
    To change the threshold from t → t' WITHOUT revealing the secret,
    we simply re-run the VSS setup with the same secret and new threshold.
    The secret is preserved, old shares are replaced with fresh ones.

    This is equivalent to the proactive re-sharing approach and is safe
    because the secret itself never leaves this object.
"""

import secrets
from typing import List, Optional

from core.group_params import Q,P
from vault.pedersen_vss import PedersenVSS
from core.commitment import pedersen_commit
from core.field_arithmetic import poly_eval

class DynamicThresholdVault:
    """
    Cryptographic vault with dynamic threshold adjustment.

    Wraps PedersenVSS and allows the threshold to be raised or lowered
    at any time without ever exposing the underlying secret.
    """


    def __init__(self, secret, blinding, shares, commitments, threshold, n):
        self.secret = secret          # kept in memory, never transmitted
        self.blinding = blinding      # pedersen blinding for coeff[0]
        self.shares = shares
        self.commitments = commitments
        self.current_threshold = threshold
        self.n = n
        self.history = []

    @classmethod
    def create(cls, secret: int, n: int, threshold: int) -> "DynamicThresholdVault":
        """Create a new vault by running VSS on the secret."""
        vss = PedersenVSS(secret, threshold, n)       # matches your constructor exactly
        shares = vss.generate_all_shares()
        commitments = vss.get_public_commitments()
        blinding = vss.r_coeffs[0]                    # ✅ r_coeffs[0] is the blinding for coeff[0]

        return cls(secret, blinding, shares, commitments, threshold, n)


    def adjust_threshold(self, new_threshold: int, reason: str = "policy update"):

        if new_threshold < 2:
            raise ValueError("Threshold must be at least 2")

        if new_threshold >= self.n:
            raise ValueError(f"Threshold must be less than n={self.n}")

        if new_threshold == self.current_threshold:
            print("Threshold unchanged")
            return

        print(f"\nAdjusting threshold {self.current_threshold} → {new_threshold} ({reason})")

        # Re-run Pedersen VSS with same secret but new threshold
        vss = PedersenVSS(self.secret, new_threshold, self.n)

        new_shares = vss.generate_all_shares()
        new_commitments = vss.get_public_commitments()

        self.blinding = vss.r_coeffs[0]

        self.shares = new_shares
        self.commitments = new_commitments

        self.history.append({
            "event": reason,
            "threshold": new_threshold,
            "n_participants": self.n,
        })

        self.current_threshold = new_threshold

        print(f"✓ Threshold adjusted to t={new_threshold}")
        print("✓ Secret never reconstructed")

    def reconstruct(self, share_ids: List[int]) -> Optional[int]:
        """Attempt to reconstruct the secret using shares from the given participant IDs."""
        selected = [s for s in self.shares if s[0] in share_ids]
        print(f"\n  🔓 Reconstruction attempt — {len(selected)} shares provided "
              f"(need {self.current_threshold + 1})")
        return PedersenVSS.reconstruct_secret(
            selected, self.commitments, self.current_threshold
        )

    def print_status(self) -> None:
        """Print a formatted summary of the vault's current state."""
        sep = "─" * 52
        print(f"\n  ┌{sep}┐")
        print(f"  │{'  VAULT STATUS':^52}│")
        print(f"  ├{sep}┤")
        print(f"  │  Participants : {self.n:<34}│")
        print(f"  │  Threshold    : t={self.current_threshold}  "
              f"(need {self.current_threshold + 1} of {self.n}){'':<20}│")
        print(f"  │  Commitments  : {len(self.commitments)} public values{'':<29}│")
        print(f"  ├{sep}┤")
        print(f"  │  History:{'':<43}│")
        for i, h in enumerate(self.history):
            line = f"    [{i+1}] t={h['threshold']}, n={h['n_participants']} — {h['event']}"
            print(f"  │{line[:52]:<52}│")
        print(f"  └{sep}┘\n")