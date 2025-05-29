# Key Establishment Protocol

A secure three-party messaging protocol developed using Python, implementing **RSA**, **AES-GCM**, **HKDF**, and **X.509 certificates** to ensure confidentiality, authenticity, and replay protection.

##  Project Summary

This project simulates a secure communication setup among three entities using modern cryptographic mechanisms. It was built as part of my **Cybersecurity Master’s coursework at the University of Limerick**.

The protocol demonstrates:
- **Asymmetric key encryption** using RSA
- **Symmetric key encryption** using AES-GCM
- **Key derivation** using HKDF
- **Identity verification** using X.509 certificates
- **Replay protection** using timestamp validation

##  Features

-  Secure key exchange using RSA
-  Session key derivation with HKDF
- Message encryption using AES-GCM
- X.509 certificate-based authentication
-  Anti-replay mechanism with timestamp verification
-  Command-line interface for secure message simulation

##  Cryptographic Concepts Implemented

| Component         | Technology Used            |
|------------------|----------------------------|
| Key Exchange     | RSA (2048-bit)             |
| Data Encryption  | AES-GCM (256-bit)          |
| Key Derivation   | HKDF (HMAC-SHA256)         |
| Auth & Identity  | X.509 Certificates         |
| Replay Protection| Timestamps & Nonce Checks  |

##  Technologies Used

- **Language:** Python 3.x
- **Libraries:** `cryptography`, `datetime`, `os`, `base64`, `secrets`
- **Tools:** OpenSSL (for cert generation)

## Project Structure

├── main.py                    # Entry point for simulation
├── certs/                     # X.509 certificates for three parties
├── keys/                      # RSA key pairs
├── utils/                     # Helper functions for encryption, validation
└── README.md                  # Project documentation
