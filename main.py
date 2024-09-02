import random
from sympy import isprime, mod_inverse

# Function to generate a random prime number within a range
def generate_prime_number(start, end):
    while True:
        num = random.randint(start, end)
        if isprime(num):
            return num

# Function to calculate the greatest common divisor
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Function to generate RSA public and private keys
def generate_rsa_keys():
    # Generate two distinct prime numbers
    p = generate_prime_number(100, 300)
    q = generate_prime_number(100, 300)
    
    while p == q:
        q = generate_prime_number(100, 300)
    
    # Calculate n (modulus) and phi (Euler's totient function)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose an integer e such that 1 < e < phi and gcd(e, phi) = 1
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # Calculate the private key d such that (d * e) % phi = 1
    d = mod_inverse(e, phi)
    
    # Return the public and private keys
    return (e, n), (d, n)

# Function to encrypt a message using the public key
def encrypt(message, public_key):
    e, n = public_key
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message

# Function to decrypt a message using the private key
def decrypt(encrypted_message, private_key):
    d, n = private_key
    decrypted_message = ''.join([chr(pow(char, d, n)) for char in encrypted_message])
    return decrypted_message

# Main function to demonstrate RSA encryption and decryption
def main():
    print("Generating RSA keys...")
    public_key, private_key = generate_rsa_keys()
    print(f"Public Key: {public_key}")
    decrypted_message = ''.join([chr(pow(char, d, n)) for char in encrypted_message])
    encrypted_message = [pow(ord(char), e, n) for char in message]
    encrypted_message = encrypt(message, public_key)
    print(f"Private Key: {private_key}")

    # Example message to encrypt and decrypt
    message = "Hello RSA!"
    print(f"\nOriginal Message: {message}")

    # Encrypt the message
    encrypted_message = encrypt(message, public_key)
    print(f"Encrypted Message: {encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt(encrypted_message, private_key)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
