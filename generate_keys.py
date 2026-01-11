# generate_keys.py
# Run once to create keys used to sign evidence and ledger blocks.

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import subprocess
import os

KEY_DIR = 'keys'
os.makedirs(KEY_DIR, exist_ok=True)

# Generate RSA private key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
with open(os.path.join(KEY_DIR, 'private_key.pem'), 'wb') as f:
    f.write(priv_pem)
print('Wrote keys/private_key.pem')

# Write public key PEM
pub_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open(os.path.join(KEY_DIR, 'public_key.pem'), 'wb') as f:
    f.write(pub_pem)
print('Wrote keys/public_key.pem')

# Optionally create a self-signed certificate using OpenSSL CLI (if you want HTTPS test cert)
# Requires openssl installed on system. Uncomment to run:
#
# subprocess.run([
#     'openssl', 'req', '-x509', '-nodes', '-days', '365',
#     '-newkey', 'rsa:2048',
#     '-keyout', os.path.join(KEY_DIR, 'server.key'),
#     '-out', os.path.join(KEY_DIR, 'server.crt'),
#     '-subj', '/CN=localhost'
# ])
# print('Wrote keys/server.key and keys/server.crt (self-signed)')

print('Key generation complete.')
