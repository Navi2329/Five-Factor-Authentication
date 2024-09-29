from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Generate RSA key pairs for MITM
mitm_private_key = RSA.generate(2048)
mitm_public_key = mitm_private_key.publickey()

# Generate RSA key pairs for the legitimate parties
alice_private_key = RSA.generate(2048)
alice_public_key = alice_private_key.publickey()

bob_private_key = RSA.generate(2048)
bob_public_key = bob_private_key.publickey()

def mitm_encrypt(message, recipient_public_key):
    cipher = PKCS1_OAEP.new(recipient_public_key)
    ciphertext = cipher.encrypt(message.encode())
    return base64.b64encode(ciphertext)

def mitm_decrypt(ciphertext, recipient_private_key):
    cipher = PKCS1_OAEP.new(recipient_private_key)
    decrypted_message = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted_message.decode()

# MITM intercepts messages from Alice to Bob
def intercept_and_forward(ciphertext, recipient_public_key):
    decrypted_message = mitm_decrypt(ciphertext, recipient_public_key)
    print("MITM Intercepted Message:", decrypted_message)
    # Forward the decrypted message to the legitimate recipient
    return mitm_encrypt(decrypted_message, recipient_public_key)

# Alice sends a message to Bob
message = "Hello Bob!"
encrypted_message = mitm_encrypt(message, bob_public_key)

# MITM intercepts and forwards the message to Bob
mitm_forwarded_message = intercept_and_forward(encrypted_message, bob_private_key)

# Bob receives the message
decrypted_message = mitm_decrypt(mitm_forwarded_message, bob_private_key)
print("Bob's Decrypted Message:", decrypted_message)
