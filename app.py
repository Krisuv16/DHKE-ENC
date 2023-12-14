from flask import Flask, render_template, request

app = Flask(__name__)

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/results', methods=['POST'])
def results():
    p = int(request.form['p'])
    alice_private_key = int(request.form['alice_private_key'])
    bob_private_key = int(request.form['bob_private_key'])

    if not is_prime(p):
        return render_template('index.html', error=f"{p} is not a prime number. Please enter a prime number.")

    primitive_root = find_primitive_root(p)

    if primitive_root is not None:
        alice_public_key = diffie_hellman_key_exchange(p, primitive_root, alice_private_key)
        bob_public_key = diffie_hellman_key_exchange(p, primitive_root, bob_private_key)

        alice_shared_secret = pow(bob_public_key, alice_private_key, p)
        bob_shared_secret = pow(alice_public_key, bob_private_key, p)

        message = request.form['message']
        message_int = [ord(char) for char in message]
        encrypted_message = xor_encrypt_decrypt(message_int, alice_shared_secret)
        decrypted_message = xor_encrypt_decrypt(encrypted_message, bob_shared_secret)
        decrypted_message_str = ''.join([chr(char) for char in decrypted_message])

        return render_template('results.html',
                               p=p,
                               primitive_root=primitive_root,
                               alice_public_key=alice_public_key,
                               bob_public_key=bob_public_key,
                               alice_shared_secret=alice_shared_secret,
                               bob_shared_secret=bob_shared_secret,
                               message=message,
                               encrypted_message=encrypted_message,
                               decrypted_message=decrypted_message_str)
    else:
        return render_template('index.html', error=f"No primitive root found for {p}. Choose a different prime.")

if __name__ == '__main__':
    app.run(debug=True)
