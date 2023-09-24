from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from cryptography.fernet import Fernet
import logging
import requests  # Import the requests library


app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables
DATA_FILE = 'encrypted_data.txt'
PASSWORDS_FILE = 'passwords.txt'
KEY_FILE = 'key.key'

# Generate a key for encryption
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)

# Load the encryption key from a file
def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, 'rb') as key_file:
        key = key_file.read()
    return key

# Encrypt data using Fernet symmetric encryption
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

# Decrypt data using Fernet symmetric encryption
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data

# Store encrypted data in a file
def store_encrypted_data(filename, encrypted_data):
    with open(filename, 'wb') as file:
        file.write(encrypted_data)

# Read encrypted data from a file
def read_encrypted_data(filename):
    with open(filename, 'rb') as file:
        encrypted_data = file.read()
    return encrypted_data

# Store passwords in a file (encrypted)
def store_password(username, password, key):
    passwords = {}
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'rb') as file:
            encrypted_passwords = file.read()
            if encrypted_passwords:
                decrypted_passwords = decrypt_data(encrypted_passwords, key)
                passwords = eval(decrypted_passwords)
    
    passwords[username] = password
    encrypted_passwords = encrypt_data(str(passwords), key)
    store_encrypted_data(PASSWORDS_FILE, encrypted_passwords)

def is_authenticated(username, password, key):
    # Load user credentials from a database or some secure storage
    # Compare the entered username and password with the stored values
    # Return True if they match, else return False
    # Example: Replace this with actual database or secure storage logic
    user_credentials = {
        'aryan': 'aryan'
    }
    
    if username in user_credentials and user_credentials[username] == password:
        return True
    
    return False


# Routes
@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
    else:
        username = None
    return render_template('index.html', username=username)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    key = load_key()
    data = request.form['data']
    encrypted_data = encrypt_data(data, key)
    store_encrypted_data(DATA_FILE, encrypted_data)
    
    # Log the encryption action
    logging.info(f"User '{session['username']}' encrypted data.")
    
    flash("Data encrypted and stored.")
    return redirect(url_for('home'))

# Modify the /decrypt route to use the user-provided encrypted data
@app.route('/decrypt', methods=['POST'])
def decrypt():
    key = load_key()
    encrypted_data = request.form['encrypted_data']  # Retrieve the encrypted data from the form
    try:
        decrypted_data = decrypt_data(encrypted_data.encode(), key)  # Decrypt the data
    except Exception as e:
        # Handle decryption errors (e.g., incorrect key or invalid data)
        decrypted_data = f"Decryption Error: {str(e)}"

    # Log the decryption action
    logging.info(f"User '{session['username']}' decrypted data.")

    return render_template('index.html', decrypted_data=decrypted_data)



# Modify the /login route to set the session variable and capture geolocation data
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    key = load_key()
    
    if is_authenticated(username, password, key):
        session['username'] = username
        
        # Capture the user's real IP address using X-Forwarded-For header if available
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # Use the ipinfo.io API to fetch geolocation data based on the client's IP address
        geo_data = get_geolocation_data(client_ip)
        
        # Log successful login including real IP address and geolocation data
        logging.info(f"User '{username}' logged in from IP address {client_ip}. Geolocation data: {geo_data}")
        
        flash("Login successful.")
    else:
        flash("Login failed. Please try again.")
    
    return redirect(url_for('home'))

# Function to fetch geolocation data from ipinfo.io API
def get_geolocation_data(ip_address):
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/json')
        data = response.json()
        return data
    except Exception as e:
        # Handle API request errors
        return f"Geolocation Error: {str(e)}"


@app.route('/logout')
def logout():
    # Log logout action
    logging.info(f"User '{session['username']}' logged out.")
    
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)
