# Flask PQC Demo Application

This project is a simple Flask web application demonstrating Post-Quantum Cryptography (PQC) using the **CRYSTALS-Kyber** (specifically Kyber512) Key Encapsulation Mechanism (KEM) combined with AES-GCM for hybrid encryption.

## Features

*   **Key Generation:** Generates Kyber512 public and private key pairs.
*   **Hybrid Encryption:**
    *   Uses the recipient's Kyber public key to encapsulate a fresh symmetric key (the shared secret).
    *   Encrypts the user's message using AES-GCM with the derived shared secret.
    *   Outputs the KEM ciphertext, AES nonce, AES ciphertext, and authentication tag.
*   **Hybrid Decryption:**
    *   Uses the recipient's Kyber private key to decapsulate the shared secret from the KEM ciphertext.
    *   Uses the derived shared secret, nonce, and tag to decrypt the AES ciphertext.
    *   Verifies the integrity and authenticity using the AES-GCM tag.
    *   Outputs the original plaintext message if successful.
*   **Web Interface:** Simple UI built with Flask, HTML, and Bootstrap.
*   **Security:** Uses Flask-Talisman for basic security headers (including CSP).

## PQC Algorithm Used: CRYSTALS-Kyber

*   **Type:** Key Encapsulation Mechanism (KEM).
*   **Security:** Chosen by NIST as a standard for Public Key Encryption / KEMs resistant to quantum computer attacks. Based on the hardness of solving learning with errors (LWE) problems over module lattices.
*   **Purpose:** Securely establish a shared secret between two parties over an insecure channel. This shared secret is then typically used with a symmetric cipher (like AES) for efficient bulk data encryption (Hybrid Encryption).

## Technology Stack

*   **Backend:** Python 3.x, Flask
*   **PQC Library:** [pycrystals](https://github.com/mkannwischer/pycrystals) (Python wrapper for CRYSTALS Kyber/Dilithium)
*   **Symmetric Crypto:** [cryptography](https://cryptography.io/en/latest/) (for AES-GCM)
*   **Frontend:** HTML, Bootstrap 5
*   **Security:** Flask-Talisman
*   **Environment:** python-dotenv

## Setup and Running

1.  **Clone the repository:**
    ```bash
    git clone <repo-url>
    cd flask-pqc-app
    ```
2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    # On macOS/Linux:
    source venv/bin/activate
    # On Windows:
    venv\Scripts\activate
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *Note: `pycrystals` might require build tools if wheels are not available for your platform/Python version.*
4.  **Set up environment variables:**
    *   Copy `.env.example` to `.env`.
    *   Edit `.env` and generate a strong `SECRET_KEY`. You can use Python:
        ```bash
        python -c 'import os; print(os.urandom(24).hex())'
        ```
    *   Set `FLASK_ENV=development` (for development) or `production` (for deployment).
5.  **Run the Flask development server:**
    ```bash
    flask run
    # Or: python app.py
    ```
6.  Open your web browser and navigate to `http://127.0.0.1:5000` (or the address provided by Flask).

## How to Use

1.  Click "Generate New Keys" to create a Kyber512 key pair. The Base64 encoded keys will be displayed.
2.  Copy the Public Key into the "Encrypt Message" section.
3.  Enter a message you want to encrypt.
4.  Click "Encrypt". The resulting KEM Ciphertext, Nonce, AES Ciphertext, and Tag (all Base64) will be shown.
5.  Copy the Private Key and all four components of the encryption result into the "Decrypt Message" section.
6.  Click "Decrypt". If the key is correct and the data hasn't been tampered with, the original message will appear. Otherwise, a decryption error will be shown.

## Security Considerations

*   This application is for **demonstration purposes only**.
*   Displaying private keys in the browser and transferring them via forms is **highly insecure** in a real-world scenario. Secure key management is critical but outside the scope of this basic demo.
*   Ensure `FLASK_ENV` is set to `production` and `DEBUG` is `False` when deploying.
*   Flask-Talisman provides essential security headers, but review and configure them according to your deployment needs.

## Project Structure
