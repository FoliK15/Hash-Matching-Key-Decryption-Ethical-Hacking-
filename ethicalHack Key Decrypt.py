from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import os

# File paths
key_private_path = *USE DESIRED FILE PATH*
emessage_path = *USE DESIRED FILE PATH*


# Loading the private key
with open(key_private_path, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None, # no passphrase required
        backend=default_backend()
    )

# Load and read the encrypted message
with open(emessage_path, "rb") as encrypted_file:
    encrypted_data = encrypted_file.read()


# Decrypt the message
try:
    pt = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    
except Exception as e:
    print("Decryption failed:", str(e))
    raise SystemExit
              
# Print result
print("\n----- Decrypted output -----\n")
try:
    # Try as UTF-8 text
    print(pt.decode("utf-8"))
except UnicodeDecodeError:
    # Not text: show a short hex preview so you still see the content in-terminal
    hex_preview = " ".join(f"{b:02x}" for b in pt[:96])
    print("[not UTF-8 text] hex preview (first 96 bytes):")

    print(hex_preview)
