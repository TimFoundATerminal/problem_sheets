import numpy as np


def discrete_normal_sample(n, mean_proportion=0.5, std_dev_proportion=0.15, num_samples=1):
    # Calculate actual mean and standard deviation based on proportions
    mean = 1 + (n - 1) * mean_proportion  # Scales from 1 to n
    std_dev = n * std_dev_proportion
    
    # Generate continuous normal samples
    continuous_samples = np.random.normal(mean, std_dev, num_samples)
    
    # Discretize and clip to range [1, n]
    discrete_samples = np.round(continuous_samples).astype(int)
    discrete_samples = np.clip(discrete_samples, 1, n)
    
    return discrete_samples


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


class RSA():
    def __init__(self, p, q, b=None):
        self.p = p
        self.q = q

        self.n = p * q
        self.totient = (p-1) * (q-1)

        self._set_exponents(b=b)

        self.public_key = (self.n, self.b)
        self.private_key = (self.p, self.q, self.a)

    def _set_exponents(self, b=None):
        """Generates and Validates the public exponent"""
        if b is None:
            self.b = 0
            while euclidean_algorithm(b, self.totient) != 1:
                self.b = discrete_normal_sample(self.totient)
        else:
            # b needs to have a multiplicative inverse
            if euclidean_algorithm(b, self.totient) != 1:
                raise(ValueError, "b needs to have gcd(b, totient) = 1")
            self.b = b

        self.a = self._calculate_private_exponent()

    def _calculate_private_exponent(self) -> int:
        """Calculates the private exponent from the public exponent"""

        # Use the extended euclidean algorithm to calculate the multiplicative inverse
        _, _, a = extended_euclidean_algorithm(self.totient, self.b)

        # Make sure that a is positive
        return (a + self.totient) % self.totient



def euclidean_test():
    pairs = [(29, 108)]
    for a, b in pairs:
        a, b = abs(a), abs(b)
        a, b = max(a, b), min(a, b)
        res = extended_euclidean_algorithm(a,b)
        # assert(res[1]*a + res[2]*b, res[0])
        print(f"{res[1]} x {a} + {res[2]} x {b} = {res[0]} = gcd({a},{b})")

def rsa_test():

    rsa = RSA(p=7, q=19, b=29)

    print(rsa.public_key)
    print(rsa.private_key)


if __name__ == "__main__":
    rsa_test()
