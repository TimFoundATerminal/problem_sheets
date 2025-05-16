
def factor_n_given_a(n, b, a) -> int:
    """Finds a factor of n given the private exponent"""

    k = b*a - 1

    return k


def gcd(a, b) -> int:
    """Where a > b and are both in Z"""

    if b == 0:
        return a

    return gcd(b, a % b)

def euclidean_algorithm(a, b):
    """Find the gcd of a and b"""

    a, b = abs(a), abs(b)
    a, b = max(a, b), min(a, b)

    return gcd(a, b)


def extended_gcd(a, b, s_1, s_2, t_1, t_2) -> tuple[int]:
    """Returns values for gcd, s, and t where a > b"""

    if b == 0:
        return a, s_1, t_1
    
    # calculate the remainder of a mod b
    r = a % b
    q = a // b

    s_3 = s_1 - (q * s_2)
    t_3 = t_1 - (q * t_2)

    # print(a, b, q, r, s_1, s_2, s_3, t_1, t_2, t_3)

    return extended_gcd(b, r, s_2, s_3, t_2, t_3)


def extended_euclidean_algorithm(a, b):
    """Find the gcd of a and b"""

    a, b = abs(a), abs(b)
    a, b = max(a, b), min(a, b)

    # recurse on remainder and b
    return extended_gcd(a, b, 1, 0, 0, 1)


def mod_inverse(a, m):
    """Returns the multiplicative inverse should it exist"""
    _, _, i = extended_euclidean_algorithm(a, m)
    return (i + m) % m


def euclidean_test():
    pairs = [(29, 108)]
    for a, b in pairs:
        a, b = abs(a), abs(b)
        a, b = max(a, b), min(a, b)
        res = extended_euclidean_algorithm(a,b)
        # assert(res[1]*a + res[2]*b, res[0])
        print(f"{res[1]} x {a} + {res[2]} x {b} = {res[0]} = gcd({a},{b})")


if __name__ == "__main__":
    # euclidean_test()

    print(mod_inverse(8684, 11021))
