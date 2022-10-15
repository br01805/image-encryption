import cv2
import rsa
import matplotlib.pyplot as plt
from rsa import common, transform, randnum


def get_primality_testing_rounds(number: int) -> int:
    """Returns minimum number of rounds for Miller-Rabing primality testing,
    based on number bitsize.
    According to NIST FIPS 186-4, Appendix C, Table C.3, minimum number of
    rounds of M-R testing, using an error probability of 2 ** (-100), for
    different p, q bitsizes are:
      * p, q bitsize: 512; rounds: 7
      * p, q bitsize: 1024; rounds: 4
      * p, q bitsize: 1536; rounds: 3
    See: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    # Calculate number bitsize.
    bitsize = rsa.common.bit_size(number)
    # Set number of rounds.
    if bitsize >= 1536:
        return 3
    if bitsize >= 1024:
        return 4
    if bitsize >= 512:
        return 7
    # For smaller bitsizes, set arbitrary number of rounds.
    return 10


def miller_rabin_primality_testing(n: int, k: int) -> bool:
    """Calculates whether n is composite (which is always correct) or prime
    (which theoretically is incorrect with error probability 4**-k), by
    applying Miller-Rabin primality testing.
    For reference and implementation example, see:
    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    :param n: Integer to be tested for primality.
    :type n: int
    :param k: Number of rounds (witnesses) of Miller-Rabin testing.
    :type k: int
    :return: False if the number is composite, True if it's probably prime.
    :rtype: bool
    """

    # prevent potential infinite loop when d = 0
    if n < 2:
        return False

    # Decompose (n - 1) to write it as (2 ** r) * d
    # While d is even, divide it by 2 and increase the exponent.
    d = n - 1
    r = 0

    while not (d & 1):
        r += 1
        d >>= 1

    # Test k witnesses.
    for _ in range(k):
        # Generate random integer a, where 2 <= a <= (n - 2)
        a = rsa.randnum.randint(n - 3) + 1

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == 1:
                # n is composite.
                return False
            if x == n - 1:
                # Exit inner loop and continue with next witness.
                break
        else:
            # If loop doesn't break, n is composite.
            return False

    return True


def is_prime(number: int) -> bool:
    """Returns True if the number is prime, and False otherwise.
    >>> is_prime(2)
    True
    >>> is_prime(42)
    False
    >>> is_prime(41)
    True
    """

    # Check for small numbers.
    if number < 10:
        return number in {2, 3, 5, 7}

    # Check for even numbers.
    if not (number & 1):
        return False

    # Calculate minimum number of rounds.
    k = get_primalitMy_testing_rounds(number)

    # Run primality testing with (minimum + 1) rounds.
    return miller_rabin_primality_testing(number, k + 1)


def get_prime(nbits: int) -> int:
    """Returns a prime number that can be stored in 'nbits' bits.
    >>> p = getprime(128)
    >>> is_prime(p-1)
    False
    >>> is_prime(p)
    True
    >>> is_prime(p+1)
    False
    >>> from encrypt_rsa import common
    >>> common.bit_size(p) == 128
    True
    """

    assert nbits > 3  # the loop will hang on too small numbers

    while True:
        integer = randnum.read_random_odd_int(nbits)

        # Test for primeness
        if is_prime(integer):
            return integer

            # Retry if not prime


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
    p_prime = get_prime(length)
    q_prime = get_prime(length)
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
            img[i, j] = [c_r, c_g, c_b]
    return img


def image_decryption(img, d_private, n_modulus, row, col):
    for i in range(0, row):
        for j in range(0, col):
            red, green, blue = enc[i][j]
            m_r = modular_exponentiation(red, d_private, n_modulus)
            m_g = modular_exponentiation(green, d_private, n_modulus)
            m_b = modular_exponentiation(blue, d_private, n_modulus)
            img[i, j] = [m_r, m_g, m_b]
    return img


rgb_img = cv2.imread('/Users/brianrawls/Downloads/rgb_bird.jpeg')

plt.imshow(rgb_img, cmap="gray")

row, col = rgb_img.shape[0], rgb_img.shape[1]

p_prime, q_prime, e, n_modulus, d_private = gen_keys(5)

encrypted_img = image_encryption(rgb_img, e, n_modulus, row, col)

plt.imshow(encrypted_img, cmap="gray")

decrypted_img = image_decryption(encrypted_img, d_private, n_modulus, row, col)

plt.imshow(decrypted_img, cmap="gray")

print("done")
