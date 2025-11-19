from pathlib import Path 
import hashlib, sys

from cryptography.hazmat.primitives import serialization, padding as sympad
from cryptography.hazmat.primitives.asymmetric import padding as rsapad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes 

#file paths
AESfile = *USE DESIRED FILE PATH*
HASHESfile = *USE DESIRED FILE PATH*
MESSAGEfile = *USE DESIRED FILE PATH*
RSAfile = *USE DESIRED FILE PATH*


## helper functions to keep the code clean

# computes MD5 hash of bytes and returns hex string
def med5_hex(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()

# opens file and returns its bytes
def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

# turns bytes into utf-8/utf-16 string (readable text)
def decode_text(b: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-8"):
        try:
            return b.decode(enc)
        except Exception:
            pass
    return b.decode("latin-1", errors="replace") 

# Hashes bytes with MD5 and returns lowercase hex string
def md5_hex(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()

# Read target hashes
import re

TARGET_AES_MD5 = None
TARGET_MASTER_MD5 = None

for f in sorted(HASHESfile.iterdir(), key=lambda p: p.name):
    name = f.name.lower()
    h = read_bytes(f).decode("utf-8").strip()
    if "aes" in name:
        TARGET_AES_MD5 = h
    elif "master" in name:
        TARGET_MASTER_MD5 = h

print(f"Target AES MD5: {TARGET_AES_MD5}")
print(f"Target Master MD5: {TARGET_MASTER_MD5}")

# Function for mathing hashes
def find_matching_file(target_hash: str, directory: Path) -> Path | None:
    for f in sorted(directory.iterdir(), key=lambda p: p.name):
        if f.is_file():
            file_hash = med5_hex(read_bytes(f))
            print(f"Computed MD5 for {f.name}: {file_hash}")
            if file_hash == TARGET_AES_MD5:
                print(f"Match found! The file '{f.name}' matches the target hash.")
                return f
    return None

# Function to load all RSA private keys
def load_rsa_private_keys(rsa_dir: Path):
    privs = []
    for p in sorted(rsa_dir.glob("*")):
        if not p.is_file():
            continue
        raw = p.read_bytes()
        for loader in (serialization.load_pem_private_key, serialization.load_der_private_key):
            try:
                k = loader(raw, password=None)    # succeeds only for private keys
                privs.append((p.name, k))
                break
            except Exception:
                pass
    return privs

# Function to decrypt AES key using RSA private keys
def decrypt_aes_key(privs, blob: bytes):
    try:
        yield "PKCS1v15", privs.decrypt(blob, rsapad.PKCS1v15())
    except Exception:
        pass
    try:
        yield "OAEP-SHA1", privs.decrypt(
            blob,
            rsapad.OAEP(
                mgf=rsapad.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
    except Exception:
        pass

#Trying each private key to decrypt the AES key
FOUND_AES_KEY = None
FOUND_INFO = None
print("\n----- Trying to find and decrypt AES key -----\n")
priv_keys = load_rsa_private_keys(RSAfile)
if not priv_keys:
    raise SystemExit("[!] No RSA private keys found.")

for aes_path in sorted(AESfile.glob("*")):
    if not aes_path.is_file():
        continue
    enc_blob = read_bytes(aes_path)

    for key_name, priv in priv_keys:
        for pad_name, pt in decrypt_aes_key(priv, enc_blob):
            # Only valid AES key sizes
            if len(pt) in (16, 24, 32) and md5_hex(pt) == TARGET_AES_MD5:
                FOUND_AES_KEY = pt
                FOUND_INFO = {
                    "aes_enc_file": aes_path.name,
                    "rsa_priv_file": key_name,
                    "rsa_padding": pad_name,
                    "length": len(pt),
                    "md5": TARGET_AES_MD5,
                }
                break
        if FOUND_AES_KEY:
            break
    if FOUND_AES_KEY:
        break

if not FOUND_AES_KEY:
    raise SystemExit("[!] No AES key matched TARGET_AES_MD5.")

# Print the single, correct key
print("[+] Correct AES session key located:")
print(f"    Encrypted file : {FOUND_INFO['aes_enc_file']}")
print(f"    Private key    : {FOUND_INFO['rsa_priv_file']}  (padding={FOUND_INFO['rsa_padding']})")
print(f"    Key length     : {FOUND_INFO['length']} bytes")
print(f"    MD5(key)       : {FOUND_INFO['md5']}  [OK]")
print(f"    Key (hex)      : {FOUND_AES_KEY.hex()}\n")


# Function to decrypt message files using AES key
ZERO_IV = b"\x00" * 16

def decrypt_cbc_zero_iv(key: bytes, ct: bytes) -> bytes | None:
    """AES-CBC with IV=0...0; try PKCS#7 first, then no-pad."""
    dec = Cipher(algorithms.AES(key), modes.CBC(ZERO_IV), backend=default_backend()).decryptor()
    out = dec.update(ct) + dec.finalize()
    # Try to remove PKCS#7 padding
    try:
        un = sympad.PKCS7(128).unpadder()
        return un.update(out) + un.finalize()
    except Exception:
        # If unpadding fails, return raw (no-pad) bytes
        return out

print("== Decrypting messages with AES-CBC (IV = 00..00) ==")
FOUND = None  # (fname, pt)

for p in sorted(MESSAGEfile.glob("*")):
    if not p.is_file():
        continue
    ct = read_bytes(p)
    pt = decrypt_cbc_zero_iv(FOUND_AES_KEY, ct)
    if pt is None:
        continue
    if md5_hex(pt) == TARGET_MASTER_MD5:
        FOUND = (p.name, pt)
        break

if not FOUND:
    raise SystemExit("[!] No message matched TARGET_MASTER_MD5 using AES-CBC with zero IV.")

# Pretty output (proof + plaintext)
fname, pt = FOUND
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

print("\n[+] Secret master message located (AES-CBC, IV=00..00):")
print(f"    Message file   : {fname}")
print(f"    Key length     : {len(FOUND_AES_KEY)} bytes")
print(f"    IV (hex)       : {ZERO_IV.hex()}")
print(f"    MD5(plaintext) : {md5_hex(pt)} == {TARGET_MASTER_MD5}  [OK]")

print("\n----- BEGIN PLAINTEXT -----")
print(decode_text(pt).rstrip())

print("-----  END PLAINTEXT  -----\n")
