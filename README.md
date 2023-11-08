
# Secure Communication Protocol Implementation

## Student Information
- **Name**: Asawira Emaan Khan
- **Course**: CS3002 Information Security
- **Date**: October 26, 2023
- **Professor**: Ms. Urooj Ghani
- **Institution**: Foundation for Advancement of Science and Technology (FAST) - National University of Computer & Emerging Sciences (NUCES)

## Introduction
This project implements a secure communication system using cryptographic primitives to ensure confidentiality, integrity, and authenticity of data during transmission.

## Cryptographic Primitives Implemented
1. **AES (Advanced Encryption Standard)** - Symmetric encryption.
2. **SHA256** - Cryptographic hash function for data integrity.
3. **Diffie-Hellman Key Exchange** - Establishes a shared secret key over an insecure channel.
4. **RSA (Rivest–Shamir–Adleman)** - Asymmetric encryption algorithm.
5. **PKI (Public Key Infrastructure)** - Manages digital certificates and public-key encryption.

## Implementation
The `implementationCode.py` script includes AES for data encryption, SHA256 for integrity checks, RSA for asymmetric encryption and signatures, Diffie-Hellman for key exchange, and a client-server setup for secure data exchanges.

```python
# Python code snippets showcasing implementation of cryptographic tools
```

## Challenges and Solutions
1. **Algorithm Complexity** - Resolved through extensive research and test cases.
2. **Synchronization Issues** - Addressed by implementing a handshake protocol.
3. **Data Padding for AES** - Solved using secure padding techniques.

## Design Choices
- Libraries like `Crypto.Cipher` and the built-in `socket` library in Python were used.
- AES was chosen for encryption due to its security and industry recognition.
- RSA was selected for secure key exchanges.

## Testing
Tests within the main function validate the cryptographic primitives and ensure secure client-server communication.

## User Interface
A user-friendly UI was developed using the `tkinter` library, allowing easy encrypted messaging.

## Conclusion
The project delivers a robust system for encrypted communication, demonstrating the importance of cryptography in securing digital information.

## References
List of academic papers and resources referenced for the implementation.
