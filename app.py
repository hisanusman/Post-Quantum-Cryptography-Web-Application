# app.py
import os
from flask import Flask, render_template, request, flash, redirect, url_for
from dotenv import load_dotenv
from flask_talisman import Talisman

# Import our PQC utility functions
from pqc_utils import (
    generate_kyber_keys,
    encrypt_message,
    decrypt_message,
    bytes_to_base64,
    base64_to_bytes
)

load_dotenv() # Load environment variables from .env

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-fallback-secret-key-for-dev')

# --- Security Headers ---
# Content Security Policy (CSP) - adjust as needed, especially script-src if using inline JS or external JS libs
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js' # Allow Bootstrap JS
     ],
    'style-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css' # Allow Bootstrap CSS
    ]
}
# In app.py
# Temporarily disable automatic HTTPS redirection for testing
talisman = Talisman(app, content_security_policy=csp, force_https=False)

# --- Routes ---

@app.route('/', methods=['GET'])
def index():
    """Renders the main page."""
    # Pass empty strings initially or retrieve from session if implemented
    return render_template('index.html',
                           pk_b64="", sk_b64="",
                           message_to_encrypt="",
                           kem_ct_b64="", nonce_b64="", aes_ct_b64="", tag_b64="",
                           decrypted_message="",
                           encryption_error=None, decryption_error=None)

@app.route('/generate', methods=['POST'])
def generate():
    """Generates Kyber keys and displays them."""
    pk_bytes, sk_bytes = generate_kyber_keys()
    pk_b64 = bytes_to_base64(pk_bytes)
    sk_b64 = bytes_to_base64(sk_bytes)

    if not pk_b64 or not sk_b64:
        flash('Error generating keys.', 'danger')
        return redirect(url_for('index'))

    flash('Keys generated successfully!', 'success')
    # Render index again, passing the generated keys
    return render_template('index.html', pk_b64=pk_b64, sk_b64=sk_b64)


@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypts a message using the provided public key."""
    pk_b64 = request.form.get('public_key_enc')
    message = request.form.get('message_to_encrypt')
    sk_b64_display = request.form.get('private_key_display_enc') # Keep private key in view if it was there

    if not pk_b64 or not message:
        flash('Public key and message are required for encryption.', 'warning')
        return render_template('index.html', pk_b64=pk_b64, sk_b64=sk_b64_display, message_to_encrypt=message)

    pk_bytes = base64_to_bytes(pk_b64)
    if not pk_bytes:
        flash('Invalid Public Key format (must be Base64).', 'danger')
        return render_template('index.html', pk_b64=pk_b64, sk_b64=sk_b64_display, message_to_encrypt=message)

    kem_ct_bytes, nonce_bytes, aes_ct_bytes, tag_bytes = encrypt_message(pk_bytes, message)

    if not kem_ct_bytes: # Check if encryption failed
        flash('Encryption failed. Check server logs for details.', 'danger')
        return render_template('index.html', pk_b64=pk_b64, sk_b64=sk_b64_display, message_to_encrypt=message, encryption_error="Encryption failed")

    # Encode results to Base64 for display/use in decryption form
    kem_ct_b64 = bytes_to_base64(kem_ct_bytes)
    nonce_b64 = bytes_to_base64(nonce_bytes)
    aes_ct_b64 = bytes_to_base64(aes_ct_bytes)
    tag_b64 = bytes_to_base64(tag_bytes)

    flash('Message encrypted successfully!', 'success')
    return render_template('index.html',
                           pk_b64=pk_b64,
                           sk_b64=sk_b64_display, # Keep SK in view if present
                           message_to_encrypt=message,
                           kem_ct_b64=kem_ct_b64,
                           nonce_b64=nonce_b64,
                           aes_ct_b64=aes_ct_b64,
                           tag_b64=tag_b64)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypts the ciphertext using the provided private key and components."""
    sk_b64 = request.form.get('private_key_dec')
    kem_ct_b64 = request.form.get('kem_ciphertext_dec')
    nonce_b64 = request.form.get('nonce_dec')
    aes_ct_b64 = request.form.get('aes_ciphertext_dec')
    tag_b64 = request.form.get('tag_dec')
    pk_b64_display = request.form.get('public_key_display_dec') # Keep public key in view if it was there

    # Keep original encrypted values in view
    form_values = {
        'pk_b64': pk_b64_display,
        'sk_b64': sk_b64,
        'kem_ct_b64': kem_ct_b64,
        'nonce_b64': nonce_b64,
        'aes_ct_b64': aes_ct_b64,
        'tag_b64': tag_b64
    }

    if not all([sk_b64, kem_ct_b64, nonce_b64, aes_ct_b64, tag_b64]):
        flash('All fields (Private Key, KEM CT, Nonce, AES CT, Tag) are required for decryption.', 'warning')
        return render_template('index.html', **form_values)

    # Decode Base64 inputs
    sk_bytes = base64_to_bytes(sk_b64)
    kem_ct_bytes = base64_to_bytes(kem_ct_b64)
    nonce_bytes = base64_to_bytes(nonce_b64)
    aes_ct_bytes = base64_to_bytes(aes_ct_b64)
    tag_bytes = base64_to_bytes(tag_b64)

    if not all([sk_bytes, kem_ct_bytes, nonce_bytes, aes_ct_bytes, tag_bytes]):
         flash('Invalid Base64 format in one or more decryption fields.', 'danger')
         return render_template('index.html', **form_values, decryption_error="Invalid Base64 format")

    decrypted_message = decrypt_message(sk_bytes, kem_ct_bytes, nonce_bytes, aes_ct_bytes, tag_bytes)

    if decrypted_message is None:
        flash('Decryption failed. Incorrect key, tampered data, or invalid format.', 'danger')
        return render_template('index.html', **form_values, decryption_error="Decryption Failed")

    flash('Message decrypted successfully!', 'success')
    return render_template('index.html',
                           **form_values, # Show the inputs used
                           decrypted_message=decrypted_message)

# --- Run the App ---
if __name__ == '__main__':
    # Use 0.0.0.0 to be accessible on the network (adjust if needed)
    # Debug=False for production/deployment (Talisman might enforce this)
    app.run(host='0.0.0.0', port=5000, debug=(os.environ.get('FLASK_ENV') == 'development'))