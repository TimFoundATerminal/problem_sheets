from euclidean import euclidean_algorithm, extended_euclidean_algorithm
import numpy as np


def discrete_normal_sample(n, mean_proportion=0.5, std_dev_proportion=0.15):
    # Calculate actual mean and standard deviation based on proportions
    mean = 1 + (n - 1) * mean_proportion  # Scales from 1 to n
    std_dev = n * std_dev_proportion
    
    # Generate continuous normal samples
    continuous_samples = np.random.normal(mean, std_dev, 1)
    
    # Discretize and clip to range [1, n]
    discrete_samples = np.round(continuous_samples).astype(int)
    discrete_samples = np.clip(discrete_samples, 1, n)
    
    return discrete_samples.item()


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
            while euclidean_algorithm(self.b, self.totient) != 1:
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
    
    def encrypt(self, plaintext: int) -> int:
        """Encrypts the input using the public keys"""

        return (plaintext**self.b) % self.n
    
    def decrypt(self, ciphertext: int) -> int:
        """Decrypts the ciphertext using the private key"""

        return (ciphertext**self.a) % self.n

        

def rsa_test():

    # rsa = RSA(p=7, q=19)
    rsa = RSA(p=7, q=19, b=29)

    print(rsa.public_key)
    print(rsa.private_key)

    plaintext = 92
    ciphertext = rsa.encrypt(plaintext)
    print(ciphertext)
    result = rsa.decrypt(ciphertext)
    print(result)


if __name__ == "__main__":
    rsa_test()