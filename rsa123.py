import random
from sympy import isprime


def generate_large_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1
        if isprime(candidate):
            return candidate


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def encrypt_rsa(plain_text, public_key):
    e, n = public_key
    return pow(plain_text, e, n)


def decrypt_rsa(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)


def generate_rsa_keys(bits):
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = pow(e, -1, phi)
    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key
