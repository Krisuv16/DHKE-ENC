def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def is_primitive_root(g, p):
    for i in range(2, int((p - 1)**0.5) + 1):
        if pow(g, (p - 1) // i, p) == 1:
            return False
    return True

def find_primitive_root(p):
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g
    return None

def diffie_hellman_key_exchange(p, g, private_key):
    public_key = pow(g, private_key, p)
    return public_key

def xor_encrypt_decrypt(message, key):
    # Initialize an empty list to store the result
    encrypted_message = []

    # Iterate through each character in the message
    for char in message:
        # XOR the character with the key and append the result to the list
        encrypted_char = char ^ key
        encrypted_message.append(encrypted_char)

    # Return the list of XORed characters
    return encrypted_message


def main():
    print("Diffie-Hellman Key Exchange and XOR Encryption/Decryption Program")

    # User input for prime number
    p = int(input("Enter a prime number (p): "))

    # Check if p is prime
    if not is_prime(p):
        print(f"{p} is not a prime number. Please enter a prime number.")
        return

    # Find a primitive root modulo p
    primitive_root = find_primitive_root(p)

    if primitive_root is not None:
        print(f"A primitive root modulo {p} is: {primitive_root}")
    else:
        print(f"No primitive root found for {p}. Choose a different prime.")
        return

    # User input for private keys
    alice_private_key = int(input("Enter Alice's private key: "))
    bob_private_key = int(input("Enter Bob's private key: "))

    # Key exchange
    alice_public_key = diffie_hellman_key_exchange(p, primitive_root, alice_private_key)
    bob_public_key = diffie_hellman_key_exchange(p, primitive_root, bob_private_key)

    # Display public keys
    print("\nKey Exchange:")
    print(f"Alice's public key: {alice_public_key}")
    print(f"Bob's public key: {bob_public_key}")

    # Shared secret calculation
    alice_shared_secret = pow(bob_public_key, alice_private_key, p)
    bob_shared_secret = pow(alice_public_key, bob_private_key, p)

    # Display shared secrets
    print("\nShared Secrets:")
    print(f"Alice's shared secret: {alice_shared_secret}")
    print(f"Bob's shared secret: {bob_shared_secret}")

    # Encryption and Decryption using XOR
    message = input("\nEnter the message to be encrypted: ")

    # Convert the message to a list of integers
    message_int = [ord(char) for char in message]

    # Alice encrypts the message
    encrypted_message = xor_encrypt_decrypt(message_int, alice_shared_secret)

    # Display encrypted message
    print("\nEncryption:")
    print(f"Original message: {message}")
    print(f"Encrypted message: {encrypted_message}")

    # Bob decrypts the message
    decrypted_message = xor_encrypt_decrypt(encrypted_message, bob_shared_secret)

    # Convert the decrypted message back to characters
    decrypted_message_str = ''.join([chr(char) for char in decrypted_message])

    # Display decrypted message
    print("\nDecryption:")
    print(f"Decrypted message: {decrypted_message_str}")

if __name__ == "__main__":
    main()
