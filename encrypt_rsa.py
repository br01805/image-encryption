import logging
from rsa import randnum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('RSA')


def gcd_extended(x, n):
    p = 0  # Declare and assign value p.
    newp = 1  # Declare and assign value newp.
    a = n  # Declare value a to distinguish against value n, the input value.
    b = x  # Declare and initialize value b to value x.
    while b != 0:  # setup the logic of the while loop, will continue until the remainder is 0.
        q = a // b  # Calculate the quotient value by divding the a and b. Both are integers, will provide an integer value.
        r = a % b  # Calculate the remainder value.
        tempp = (p - newp * q) % n  # Calculation step for pi = (pi-2) - (pi-1)(qi-2)mod(n).
        p = newp  # Assigning p to newp, first one, then after each loop with change to the newp calculated from the prior loop.
        newp = tempp  # Newp is assigned to the value of the tempp calculated from this iteration.
        a = b  # Assign the current dividend to the current divisor.
        b = r  # Assign the current divisor to the current remainder value.
        if b == 1:  # Check condition, if the divisor is equal to 1, the return the newp
            return newp
    if a > 1:  # Condition to check if an inverse exists
        return "No Inverse"


def modular_exponentiation(a, d, n):
    r = 1
    while d != 0:
        if d % 2 == 1:
            r = ((r % n) * (a % n)) % n
        a = ((a % n) * (a % n)) % n
        d >>= 1
    return r


def gen_keys(length: int):
    p_prime = randnum.read_random_odd_int(length)
    q_prime = randnum.read_random_odd_int(length)
    e = 65537  # This is standard for E
    n_modulus = p_prime * q_prime
    euler_totient = (p_prime - 1) * (q_prime - 1)
    d_private = gcd_extended(e, euler_totient)
    return p_prime, q_prime, e, n_modulus, d_private


enc = [[0 for x in range(3000)] for y in range(3000)]


def image_encryption(img, e, n_modulus, row, col):
    for i in range(0, row):
        for j in range(0, col):
            red, green, blue = img[i, j]
            c_r = modular_exponentiation(red, e, n_modulus)
            c_g = modular_exponentiation(green, e, n_modulus)
            c_b = modular_exponentiation(blue, e, n_modulus)
            enc[i][j] = [c_r, c_g, c_b]
            c_r = c_r % 256
            c_g = c_g % 256
            c_b = c_b % 256
            # logger.info(f'encrypted array {red} {green} {blue} -> {c_r} {c_g} {c_b}')
            img[i, j] = [c_r, c_g, c_b]
    return img


def image_decryption(img, d_private, n_modulus, row, col):
    for i in range(0, row):
        for j in range(0, col):
            red, green, blue = enc[i][j]
            m_r = modular_exponentiation(red, d_private, n_modulus)
            m_g = modular_exponentiation(green, d_private, n_modulus)
            m_b = modular_exponentiation(blue, d_private, n_modulus)
            # logger.info(f'decrypted array {red} {green} {blue} -> {m_r} {m_g} {m_b}')
            img[i, j] = [m_r, m_g, m_b]
    return img