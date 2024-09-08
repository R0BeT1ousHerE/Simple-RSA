import random
from sympy import mod_inverse, isprime


def generate_large_prime(min_value=100, max_value=500):
    """Generate a large prime number within the given range."""
    while True:
        num = random.randint(min_value, max_value)
        if isprime(num):
            return num


def gcd(a, b):
    """Compute the greatest common divisor using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a


def find_coprime(phi):
    """Find a coprime number to phi."""
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    return e


def rsa_keypair():
    """Generate RSA public and private key pair."""
    p = generate_large_prime()
    q = generate_large_prime()

    while p == q:  # Ensure p and q are distinct
        q = generate_large_prime()

    n = p * q
    phi = (p - 1) * (q - 1)

    e = find_coprime(phi)
    d = mod_inverse(e, phi)

    return (e, n), (d, n)


def rsa_encrypt(plaintext, public_key):
    """Encrypt a plaintext message using the RSA public key."""
    e, n = public_key
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    return ciphertext


def rsa_decrypt(ciphertext, private_key):
    """Decrypt a ciphertext message using the RSA private key."""
    d, n = private_key
    decrypted_message = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return decrypted_message


def save_keys_to_file(public_key, private_key, filename="rsa_keys.txt"):
    """Save RSA keys to a file."""
    with open(filename, "w") as file:
        file.write(f"Public Key: {public_key}\n")
        file.write(f"Private Key: {private_key}\n")
    print(f"Keys saved to {filename}")


def read_keys_from_file(filename="rsa_keys.txt"):
    """Read RSA keys from a file."""
    try:
        with open(filename, "r") as file:
            lines = file.readlines()
            public_key = eval(lines[0].split(": ")[1])
            private_key = eval(lines[1].split(": ")[1])
        return public_key, private_key
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return None, None


def main():
    print("Generating RSA keys...")
    public_key, private_key = rsa_keypair()
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    # Save keys to a file
    save_keys_to_file(public_key, private_key)

    # Read keys from a file (for demonstration)
    pub_key, priv_key = read_keys_from_file()
    if pub_key and priv_key:
        print("\nKeys loaded from file.")
        print(f"Loaded Public Key: {pub_key}")
        print(f"Loaded Private Key: {priv_key}")

    # Encrypt and decrypt a sample message
    message = "RSA Algorithm in Action!"
    print(f"\nOriginal Message: {message}")

    encrypted_msg = rsa_encrypt(message, public_key)
    print(f"Encrypted Message: {encrypted_msg}")

    decrypted_msg = rsa_decrypt(encrypted_msg, private_key)
    print(f"Decrypted Message: {decrypted_msg}")


if __name__ == "__main__":
    main()
