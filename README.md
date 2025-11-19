
<h1 align="center">🔐 Hash-Matching • Key-Decryption • Ethical-Hacking (Python)</h1>

<p align="center">
  <a href="https://img.shields.io/badge/python-3.10%2B-blue"><img src="https://img.shields.io/badge/python-3.10%2B-blue" /></a>
  <img src="https://img.shields.io/badge/crypto-cryptography%20lib-success" />
  <img src="https://img.shields.io/badge/status-course%20project-lightgrey" />
</p>

<p align="center">Locate the right RSA private key → unwrap the AES session key → decrypt the target message, with MD5 verification at each step.</p>

---

##  Overview
This repository demonstrates how Python can be used to perform **ethical hacking workflows**: verifying hashes, unwrapping AES session keys encrypted with RSA, and decrypting messages—while providing clear, reproducible proof via MD5 checks.

---

##  Hash Test
A small Python utility that lets you point at a directory of files and **match a provided MD5** against each file’s contents.  
Use it to quickly find which file equals a known hash (e.g., the **plaintext message MD5** or **plaintext AES key MD5**).

> **Why it matters:** prevents false positives—only exact plaintext bytes that match the ground-truth hash are accepted.

---

##  Key Decrypt
A focused script that uses **any RSA private key** to decrypt a message that was encrypted with the corresponding **RSA public key**.  
It prints the **plaintext** of that decryption (when successful) and can be used to validate RSA padding/mode assumptions.

---

##  AES Decrypt
A simple script that loads a given **AES key** and **decrypts a message**, then prints the **plaintext** directly in the terminal.  
For this dataset, the final step uses **AES-CBC with an all-zero IV** and removes **PKCS#7 padding** (with a no-pad fallback).

---

##  Orchestrator 
This is the end-to-end driver. It expects a dataset containing:
- `aes/` — RSA-encrypted AES session keys  
- `hashes/` — MD5 of the **plaintext AES key** and **plaintext message**  
- `messages/` — AES-encrypted messages  
- `rsa/` — many RSA keys (only **private keys** decrypt)

**What it does:**
1. Prints both target MD5 values (AES key + message).  
2. Tries each **RSA private key** against each file in `aes/` to unwrap a candidate AES key.  
3. Compares **MD5(candidate AES key)** to the target AES key MD5 and stops on the **match**.  
4. Uses the winning AES key to decrypt all files in `messages/` with **AES-CBC (IV=00…00)**.  
5. Compares **MD5(plaintext)** to the target message MD5 and stops on the **match**.  
6. Prints a human-readable plaintext and saves artifacts.

