from typing import List, Tuple


def mod_inv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def poly_eval(coeffs: List[int], x: int, q: int) -> int:
    result = 0

    for coeff in reversed(coeffs):
        result = (result * x + coeff) % q

    return result


def lagrange_interpolate(shares: List[Tuple[int, int]], q: int) -> int:
    """
    Reconstruct f(0) using Lagrange interpolation.
    Ensures all participant IDs (x-values) are unique.
    """

    # Extract x-values
    x_values = [x for x, _ in shares]

    # Check for duplicates
    if len(x_values) != len(set(x_values)):
        raise ValueError(
            "Duplicate participant IDs detected. "
            "Secret reconstruction requires distinct shares."
        )

    secret = 0
    n = len(shares)

    for i in range(n):
        xi, yi = shares[i]

        numerator = 1
        denominator = 1

        for j in range(n):
            if i == j:
                continue

            xj, _ = shares[j]

            numerator = (numerator * (-xj)) % q
            denominator = (denominator * (xi - xj)) % q

        lagrange_coeff = numerator * pow(denominator, q - 2, q)
        secret = (secret + yi * lagrange_coeff) % q

    return secret