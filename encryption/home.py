from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure random key

# Generate a random encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

@app.route('/')
def home():
    return render_template('encrypt_decrypt.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = request.form['message']
    try:
        encrypted_message = cipher_suite.encrypt(message.encode())
        flash('Message encrypted successfully', 'success')
        return render_template('encrypt_decrypt.html', encrypted_message=encrypted_message.decode())
    except Exception as e:
        flash(f'Encryption error: {str(e)}', 'error')
        return redirect(url_for('home'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_message = request.form['encrypted_message']
    try:
        decrypted_message = cipher_suite.decrypt(encrypted_message.encode())
        flash('Message decrypted successfully', 'success')
        return render_template('encrypt_decrypt.html', decrypted_message=decrypted_message.decode())
    except Exception as e:
        flash(f'Decryption error: {str(e)}', 'error')
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
