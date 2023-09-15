import rsa
import os
import hashlib


if not os.path.exists("Alice"):
    os.makedirs("Alice")

publickey, privatevkey = rsa.newkeys(512)

with open("Alice/publickey.pem", "wb") as public_file:
    public_file.write(publickey.save_pkcs1('PEM'))
with open("Alice/privatekey.pem", "wb") as private_file:
    private_file.write(privatevkey.save_pkcs1('PEM'))


if not os.path.exists("Bob"):
    os.makedirs("Bob")

fingerprint = hashlib.sha1(publickey.save_pkcs1()).hexdigest()
with open("Bob/fingerprint.txt", "w") as fingerprint_file:
    fingerprint_file.write(fingerprint)

print("Keys and fingerprint generated successfully.")
