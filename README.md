# Encryption-Decryption-tool-AES-RSA-Caesar-

A Python GUI application for encrypting and decrypting text and files using classic and modern cryptographic algorithms. Built with a simple interface for learning and performing basic encryption operations.

Features

Text Encryption & Decryption

Caesar Cipher: Encrypt and decrypt text using a configurable shift value.

AES (CBC): Encrypt and decrypt text using AES in CBC mode with a Base64-encoded key.

RSA: Generate public/private key pairs, encrypt text using the public key, and decrypt using the private key.

File Encryption & Decryption

AES File Encryption: Encrypt any file using a password-based encryption key.

File Decryption: Decrypt .enc files using the same password used during encryption.

Multiple File Types: Supports encrypting files of different formats.

Requirements

Python 3.x

PyCryptodome

Installation

Clone the repository:

git clone https://github.com/ayanxtr/YOUR-REPOSITORY-NAME.git

Navigate to the project directory:

cd YOUR-REPOSITORY-NAME

Install the required dependency:

pip install pycryptodome

Usage

Run the Python application:

python main.py

Replace main.py with your application's actual entry-point filename if different.

Choose the desired encryption or decryption method.

Enter the required text, key, shift value, or password.

For file operations, select a file and provide a password.

Decrypt encrypted files using the same password used during encryption.

Technologies Used

Python — Application logic

Tkinter — Graphical user interface, if used by the application

PyCryptodome — Cryptographic operations

Security Notes

Caesar Cipher is a basic educational cipher and is not secure for protecting sensitive information.

AES-CBC requires correct IV handling and appropriate integrity protection. CBC encryption alone does not authenticate encrypted data.

RSA encryption has message-size limitations; suitable padding should be used.

Use strong, unique passwords for file encryption.

Never share or commit private RSA keys or encryption passwords.

Keep backups of important files before encryption. Losing the password or required keys may make encrypted data unrecoverable.
