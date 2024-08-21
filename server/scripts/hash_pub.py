import hashlib
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import sys

# This file produces the hash of the server public key that matches the value
# of the cert object's 'subjectPublicKeyInfoDigest' field in the browser extension

# Load the public key from the file, excluding headers and footers
with open(sys.argv[1], 'rb') as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Extract the public key in DER format (binary format without headers/footers)
public_key_der = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# use this for proof input
# print(public_key_der)

# Compute the SHA256 hash of the DER formatted public key
hash_sha256_der = hashlib.sha256(public_key_der).digest()

# Base64 encode the hash
hash_base64_der = base64.b64encode(hash_sha256_der).decode()

# the last byte is =
print(hash_base64_der[:-1])
