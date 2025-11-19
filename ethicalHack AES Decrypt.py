from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pathlib import Path

# File Paths
AES_key_path = # *USE DESIRED FILE PATH*
encrypted_file_path = # *USE DESIRED FILE PATH*

# Load AES key
key = Path(AES_key_path).read_bytes()            # 32 raw ASCII bytes = 256 bits
ct = Path(encrypted_file_path).read_bytes()      # 64 bytes of raw binary ciphertext 
iv = b"\x00" * 16                                # all-zero IV for AES CBC mode

# Decrypt the message
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()

# Print result
print("\n----- Decrypted output -----\n")
try:
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

print(pt.decode('utf-8', errors='replace'))

