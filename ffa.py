import hmac
import hashlib
import io
from PIL import Image
import time
from Chacha import chacha20_encrypt, chacha20_decrypt
from Crypto.Random import get_random_bytes


def generate_key():
    return get_random_bytes(32)


def generate_nonce():
    return get_random_bytes(8)


def generate_hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def hide(image_path, data, key, nonce):
    start = time.time()
    data = data.encode("utf-8")
    encrypted_data = chacha20_encrypt(data, key, nonce)
    hmac_digest = generate_hmac_sha256(key, encrypted_data)
    img = Image.open(image_path)
    img.save("encrypted_image.jpg", "JPEG")
    with open("encrypted_image.jpg", "ab") as f:
        f.write(hmac_digest)
        f.write(encrypted_data)
    end = time.time()
    return "Data hidden in image successfully", end - start


def extract(image_path, key, nonce):
    start = time.time()
    with open(image_path, "rb") as f:
        encrypted_data = f.read()
        offset = encrypted_data.index(bytes.fromhex("FFD9"))
        f.seek(offset + 2)
        hmac_digest = f.read(32)
        encrypted_data = f.read()
    if hmac_digest != generate_hmac_sha256(key, encrypted_data):
        end = time.time()
        return "HMAC mismatch. Data is tampered"
    end = time.time()
    return chacha20_decrypt(encrypted_data, key, nonce).decode("utf-8"), end - start


start = time.time()
username = input("Enter your username: ")
password = input("Enter your password: ")
security_question = "What is your favorite color?"
answer = input(security_question + " ")
face = Image.open('face.jpg')  # path to the face image
face_byte = io.BytesIO()
face.save(face_byte, format='JPEG')
face_byte = face_byte.getvalue()
message = {}
message["username"] = username
message["password"] = password
message["security_question"] = security_question
message["answer"] = answer
message["face"] = face_byte
message = str(message)
key = generate_key()
nonce = generate_nonce()
res, time1 = hide("secret.jpg", message, key, nonce) # path to the image in which you want to hide the data
print(res)
extracted_data, time2 = extract("encrypted_image.jpg", key, nonce) # path to the image in which you have hidden the data

end = time.time()

print("Time taken to hide data in image:", str(time1)+" seconds")
print("Time taken to extract data from image:", str(time2)+" seconds")

for key, value in eval(extracted_data).items():
    if key == "face":
        face = Image.open(io.BytesIO(value))
        face.show()
    else:
        print(key + ":", value)

print("Total time taken:", str(end - start) + " seconds")
