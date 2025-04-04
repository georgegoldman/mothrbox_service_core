# 🔐 ECC Hybrid Encryption in Rust (with Multithreading)

This project demonstrates a hybrid encryption scheme using Elliptic Curve Cryptography (ECC) in Rust, now with multithreaded support for parallel processing of encryption and decryption tasks.

## 📌 Features

- 🔒 Elliptic Curve Cryptography using the p256 crate (NIST P-256 / secp256r1)

- 🔁 Hybrid encryption combining:
    - Ephemeral ECDH key exchange
    - AES-GCM authenticated symmetric encryption
- 🧵 Multithreaded execution for high-performance, parallel encryption/decryption

- 🔑 Ephemeral keys ensure forward secrecy
- ✅ Authenticated encryption with AES-GCM
- 📦 Pure Rust implementation using modern cryptographic libraries

## 🧠 Encryption Workflow

1. The receiver has a long-term ECC key pair.
2. The sender generates a one-time ephemeral key pair.
3. They derive a shared secret using ECDH (sender’s ephemeral private key + receiver’s public key).
4. The shared secret is hashed using SHA-256 to produce a symmetric AES key.
5. The message is encrypted using AES-GCM for confidentiality and integrity.
6. The sender sends the ciphertext and their ephemeral public key.
7. The receiver derives the same shared secret and decrypts the message.

# 🚀 Multithreaded Mode
- Designed for parallel message encryption/decryption.
- Uses Rust's powerful threading model (std::thread or rayon) to distribute workload.
- Ideal for systems handling multiple secure sessions/messages concurrently.

## 🧪 Dependencies
```toml
[dependencies]
p256 = "0.13.0"
aes-gcm = "0.10.1"
rand_core = "0.6.4"
rand = "0.8.5"
sha2 = "0.10.6"
hex = "0.4.3"
rayon = "1.8.0" # optional, for easier parallelism

```
## 📂 Use Cases

- Secure messaging platforms
- Encrypted file transfer services
- End-to-end encrypted applications
- Systems requiring high-throughput encryption via multithreading

