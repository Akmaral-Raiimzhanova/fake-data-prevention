# Fake Data Prevention

FastAPI project demonstrating fake data prevention using digital signatures, certificates, encryption, and JWT.

## Technologies

- Python
- FastAPI
- Cryptography
- JWT
- Swagger UI

## Project Description

This project demonstrates how fake or modified data can be detected and prevented using conventional cryptographic tools.

The system includes:

- unprotected data submission with `/send-data`
- digital signature generation with `/sign-data`
- signature verification with `/verify-data`
- certificate-based public key usage with `/certificate`
- encryption with `/encrypt-data`
- JWT-protected decryption with `/decrypt-data`
- authentication with `/login`
- protected access with `/protected-data`
- admin-only authorization with `/admin-data`

## How to Run

Install dependencies:

```bash
pip install -r requirements.txt
