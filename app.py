from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file, Response
import docker
from urllib.parse import urlparse
import random
import os
import json
import io
import csv
import base64
import uuid
import secrets
import bcrypt
import pyotp
import qrcode
from io import BytesIO
from PIL import Image
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from werkzeug.utils import secure_filename
from flask_sock import Sock
import pty
import subprocess
import select
import termios
import struct
import fcntl
import signal
import threading

# Import WebAuthn libraries
from webauthn import (generate_registration_options, verify_registration_response,
                     generate_authentication_options, verify_authentication_response)
from webauthn.helpers.structs import (PublicKeyCredentialDescriptor, 
                                    AuthenticatorSelectionCriteria,
                                    UserVerificationRequirement)

app = Flask(__name__)
sock = Sock(app)
app.secret_key = 'your_secret_key_here'  # Change this to a secure random value
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# No file size limit for uploads
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
db = SQLAlchemy(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Enhanced encryption with user-specific keys
def derive_key_from_password(password, salt=None):
    """Derive a secure encryption key from a password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    # Use PBKDF2 to derive a secure key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=100000,  # High number of iterations for security
        backend=default_backend()
    )
    
    # Derive the key from the password
    key = kdf.derive(password.encode())
    
    return key, salt

# Get encryption key for current user
def get_user_encryption_key(user_id=None):
    """Get the encryption key for the current user"""
    if user_id is None and 'user_id' in session:
        user_id = session['user_id']
    
    if user_id:
        # Get the user's password hash as a seed for key derivation
        user = User.query.get(user_id)
        if user and user.password_hash:
            # Use a combination of user-specific data and app secret
            seed = f"{user.password_hash}{app.secret_key}"
            # Derive a consistent key using a fixed salt stored in the app config
            salt = base64.b64decode(app.config.get('ENCRYPTION_SALT', base64.b64encode(os.urandom(16)).decode()))
            key, _ = derive_key_from_password(seed, salt)
            return key
    
    # Fallback to app secret key if no user is found (for backward compatibility)
    return app.secret_key.encode()[:32].ljust(32, b'0')

# Encryption and decryption functions
def encrypt_file(file_data, user_id=None):
    """Encrypt file data with AES-256 using the user's encryption key"""
    # Generate a random initialization vector
    iv = os.urandom(16)
    
    # Get the encryption key for the current user
    key = get_user_encryption_key(user_id)
    
    # Create an encryptor object
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Apply padding to the data
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    
    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data, iv

def decrypt_file(encrypted_data, iv, user_id=None):
    """Decrypt file data with AES-256 using the user's encryption key"""
    # Get the encryption key for the current user
    key = get_user_encryption_key(user_id)
    
    # Create a decryptor object
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

docker_client = docker.from_env()

# Create secure network for all containers
def ensure_secure_network():
    # Check if secure_network already exists
    networks = docker_client.networks.list(names=['secure_network'])
    if not networks:
        # Create the secure network if it doesn't exist
        docker_client.networks.create(
            name='secure_network',
            driver='bridge',
            check_duplicate=True,
            internal=False,  # Set to True if you want containers to be isolated from the internet
            labels={'purpose': 'kasm_workspace_secure_network'}
        )
        print("Created secure_network for Kasm Workspace containers")
    else:
        print("secure_network already exists")

# Ensure secure network exists when app starts
ensure_secure_network()

PREDEFINED_SERVICES = {
    'firefox': {
        'label': 'Firefox',
        'icon': 'Fx-Browser-icon-fullColor-512.png',
        'image': 'jlesage/firefox:latest',
        'internal_port': '5800/tcp',
        'environment': {}
    },
    'chrome': {
        'label': 'Chrome',
        'icon': '87865_chrome_icon.png',
        'image': 'kasmweb/chrome:1.17.0',
        'internal_port': '6901/tcp',
        'environment': {'VNC_PW': 'chrome123'}
    },
    'tor': {
        'label': 'Tor Browser',
        'icon': 'Tor_Browser_icon_(New).png',
        'image': 'kasmweb/tor-browser:1.17.0',
        'internal_port': '6901/tcp',
        'environment': {'VNC_PW': 'tor123'}
    },
    'edge': {
        'label': 'Edge',
        'icon': 'icons8-microsoft-edge-480.png',
        'image': 'kasmweb/edge:1.17.0',
        'internal_port': '6901/tcp',
        'environment': {'VNC_PW': 'edge123'}
    },
    'brave': {
        'label': 'Brave',
        'icon': 'icons8-brave-480.png',
        'image': 'kasmweb/brave:1.17.0',
        'internal_port': '6901/tcp',
        'environment': {'VNC_PW': 'brave123'}
    },
    'kali': {
        'label': 'Kali Linux',
        'icon': 'icons8-kali-linux-logo-96.png',
        'image': 'secure-kali-linux',
        'internal_port': '6901/tcp',
        'environment': {'VNC_PW': 'kali123'}
    },
    'ubuntu': {
        'label': 'Ubuntu',
        'icon': '4375122_logo_ubuntu_icon.png',
        'image': 'secure-ubuntu',
        'internal_port': '6901/tcp',
        'environment': {'VNC_PW': 'ubuntu123'}
    },
    'alpine': {
        'label': 'Alpine Linux',
        'icon': 'alpinelinux-icon.svg',
        'image': 'kasmweb/alpine-321-desktop:1.17.0',
        'internal_port': '6901/tcp',
        'environment': {'VNC_PW': 'alpine123'}
    },
    'debian': {
        'label': 'Debian',
        'icon': 'icons8-debian-96.png',
        'image': 'kasmweb/debian-bullseye-desktop:1.17.0',
        'internal_port': '6901/tcp',
        'environment': {'VNC_PW': 'debian123'}
    },
    'parrotos': {
        'label': 'Parrot Security',
        'icon': 'icons8-parrot-security-480.png',
        'image': 'kasmweb/core-parrotos-6:1.17.0',
        'internal_port': '6901/tcp',
        'environment': {'VNC_PW': 'parrot123'}
    },
    'vscode': {
        'label': 'VS Code',
        'icon': 'vscode.png',
        'image': 'codercom/code-server:latest',
        'internal_port': '8080/tcp',
        'environment': {'PASSWORD': 'vscode123'}
    },
    'open-webui': {
        'label': 'Open WebUI',
        'icon': 'openwebui.png',
        'url': 'http://localhost:12345'
    },
    'searxng': {
        'label': 'SearXNG',
        'icon': 'searxng.png',
        'url': 'http://localhost:80'
    }
}

# Assign 50 unique ports for each service, excluding 80 and 8080
PORT_EXCLUDE = {80, 8080}
BASE_PORTS = {
    'firefox': 5800,
    'chrome': 5850,
    'tor': 5900,
    'edge': 5950,
    'brave': 6000,
    'kali': 6901,
    'ubuntu': 6951,
    'alpine': 7001,
    'debian': 7051,
    'parrotos': 7101,
    'vscode': 8200,
}
for key, base in BASE_PORTS.items():
    PREDEFINED_SERVICES[key]['external_ports'] = [p for p in range(base, base+50) if p not in PORT_EXCLUDE]

# Password database model
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    url = db.Column(db.String(255), nullable=True)  # Kept for backward compatibility
    logo_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship with website URLs
    websites = db.relationship('WebsiteURL', backref='password', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        websites_list = [website.url for website in self.websites] if self.websites else []
        if self.url and self.url not in websites_list:
            websites_list.append(self.url)
            
        return {
            'id': self.id,
            'service': self.service,
            'username': self.username,
            'password': self.password,
            'category': self.category,
            'notes': self.notes,
            'url': self.url,  # Kept for backward compatibility
            'websites': websites_list,
            'logo_url': self.logo_url,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }

# Website URL model for multi-website support
class WebsiteURL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    password_id = db.Column(db.Integer, db.ForeignKey('password.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# File Vault database models
class VaultFolder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('vault_folder.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with parent folder
    parent = db.relationship('VaultFolder', remote_side=[id], backref=db.backref('subfolders', lazy=True))
    # Relationship with files in this folder
    files = db.relationship('VaultFile', backref='folder', lazy=True, cascade="all, delete-orphan")
    
    @property
    def upload_date(self):
        return self.created_at
    
    @property
    def size_formatted(self):
        # Calculate total size of all files in this folder and subfolders
        total_size = sum(file.file_size for file in self.files)
        for subfolder in self.subfolders:
            total_size += sum(file.file_size for file in subfolder.files)
        
        # Format size
        if total_size < 1024:
            return f"{total_size} B"
        elif total_size < 1024 * 1024:
            return f"{total_size / 1024:.1f} KB"
        elif total_size < 1024 * 1024 * 1024:
            return f"{total_size / (1024 * 1024):.1f} MB"
        else:
            return f"{total_size / (1024 * 1024 * 1024):.1f} GB"

class VaultFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    encrypted_data = db.Column(db.LargeBinary, nullable=False)  # Encrypted file content
    iv = db.Column(db.LargeBinary, nullable=False)  # Initialization vector for encryption
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    folder_id = db.Column(db.Integer, db.ForeignKey('vault_folder.id'), nullable=True)  # Files can be in root or in a folder
    
    @property
    def upload_date(self):
        return self.created_at
        
    @property
    def size_formatted(self):
        # Format size
        if self.file_size < 1024:
            return f"{self.file_size} B"
        elif self.file_size < 1024 * 1024:
            return f"{self.file_size / 1024:.1f} KB"
        elif self.file_size < 1024 * 1024 * 1024:
            return f"{self.file_size / (1024 * 1024):.1f} MB"
        else:
            return f"{self.file_size / (1024 * 1024 * 1024):.1f} GB"

# User settings database model
class UserSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    # Appearance
    theme = db.Column(db.String(20), default='dark')
    accent_color = db.Column(db.String(20), default='blue')
    font_size = db.Column(db.Integer, default=16)
    animations = db.Column(db.Boolean, default=True)
    # Workspace
    default_layout = db.Column(db.String(20), default='grid')
    container_timeout = db.Column(db.Integer, default=60)
    auto_save = db.Column(db.Boolean, default=True)
    persistent_storage = db.Column(db.Boolean, default=True)
    default_browser = db.Column(db.String(20), default='firefox')
    # Password Manager
    password_length = db.Column(db.Integer, default=16)
    include_uppercase = db.Column(db.Boolean, default=True)
    include_lowercase = db.Column(db.Boolean, default=True)
    include_numbers = db.Column(db.Boolean, default=True)
    include_symbols = db.Column(db.Boolean, default=True)
    enable_autofill = db.Column(db.Boolean, default=True)
    require_auth = db.Column(db.Boolean, default=True)
    admin_password = db.Column(db.String(255), default='admin')
    # Notifications
    security_notifications = db.Column(db.Boolean, default=True)
    container_notifications = db.Column(db.Boolean, default=True)
    password_notifications = db.Column(db.Boolean, default=True)
    file_notifications = db.Column(db.Boolean, default=True)
    notification_display = db.Column(db.String(20), default='all')

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns if c.name != 'id'}

    def reset_to_defaults(self):
        self.theme = 'dark'
        self.accent_color = 'blue'
        self.font_size = 16
        self.animations = True
        self.default_layout = 'grid'
        self.container_timeout = 60
        self.auto_save = True
        self.persistent_storage = True
        self.default_browser = 'firefox'
        self.password_length = 16
        self.include_uppercase = True
        self.include_lowercase = True
        self.include_numbers = True
        self.include_symbols = True
        self.enable_autofill = True
        self.require_auth = True
        self.admin_password = 'admin'
        self.security_notifications = True
        self.container_notifications = True
        self.password_notifications = True
        self.file_notifications = True
        self.notification_display = 'all'

# User model for authentication
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)  # Can be null for passwordless auth
    email = db.Column(db.String(100), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True)
    # Two-factor authentication
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    # Recovery codes
    recovery_codes = db.Column(db.Text, nullable=True)  # JSON list of hashed recovery codes
    # WebAuthn/FIDO2 fields
    webauthn_user_id = db.Column(db.String(64), unique=True, nullable=True)
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        if not self.password_hash:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def enable_totp(self):
        self.totp_secret = pyotp.random_base32()
        self.totp_enabled = True
        # Generate recovery codes
        codes = [secrets.token_hex(8) for _ in range(10)]
        # Store hashed versions
        hashed_codes = [bcrypt.hashpw(code.encode('utf-8'), bcrypt.gensalt()).decode('utf-8') for code in codes]
        self.recovery_codes = json.dumps(hashed_codes)
        return codes, self.totp_secret
    
    def verify_totp(self, token):
        if not self.totp_enabled or not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)
    
    def verify_recovery_code(self, code):
        if not self.recovery_codes:
            return False
        hashed_codes = json.loads(self.recovery_codes)
        for i, hashed_code in enumerate(hashed_codes):
            if bcrypt.checkpw(code.encode('utf-8'), hashed_code.encode('utf-8')):
                # Remove used code
                hashed_codes.pop(i)
                self.recovery_codes = json.dumps(hashed_codes)
                return True
        return False

# WebAuthn credential model
class WebAuthnCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.String(255), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)
    device_name = db.Column(db.String(100), nullable=True)
    # Relationship with user
    user = db.relationship('User', backref=db.backref('webauthn_credentials', lazy=True, cascade="all, delete-orphan"))

# Create database tables
with app.app_context():
    db.create_all()
    # Ensure default settings for admin user
    if not UserSettings.query.filter_by(username='admin').first():
        db.session.add(UserSettings(username='admin'))
        db.session.commit()
    
    # Create default admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', webauthn_user_id=str(uuid.uuid4()))
        admin_user.set_password('admin')
        db.session.add(admin_user)
        db.session.commit()

def get_user_settings(username):
    settings = UserSettings.query.filter_by(username=username).first()
    if not settings:
        settings = UserSettings(username=username)
        db.session.add(settings)
        db.session.commit()
    return settings

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find the user by username
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists and password is correct
        if user and user.check_password(password):
            # Set session variables
            session['user'] = username
            session['user_id'] = user.id
            
            # Update last login timestamp
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Check if TOTP is enabled for this user
            if user.totp_enabled:
                # Redirect to TOTP verification page
                session['awaiting_totp'] = True
                return redirect(url_for('verify_totp'))
            
            # Check if WebAuthn is available for this user
            if WebAuthnCredential.query.filter_by(user_id=user.id).first():
                # Redirect to WebAuthn verification
                session['awaiting_webauthn'] = True
                return redirect(url_for('verify_webauthn'))
            
            # If no additional authentication is required, proceed to dashboard
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template('login.html', error=error)

@app.route('/verify-totp', methods=['GET', 'POST'])
def verify_totp():
    # Check if user is in the middle of authentication
    if 'user_id' not in session or 'awaiting_totp' not in session:
        return redirect(url_for('login'))
    
    error = None
    if request.method == 'POST':
        token = request.form.get('totp_token')
        recovery_code = request.form.get('recovery_code')
        
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        # Check if user submitted a TOTP token or recovery code
        if token and user.verify_totp(token):
            # TOTP verification successful
            session.pop('awaiting_totp', None)
            return redirect(url_for('dashboard'))
        elif recovery_code and user.verify_recovery_code(recovery_code):
            # Recovery code verification successful
            session.pop('awaiting_totp', None)
            db.session.commit()  # Save the updated recovery codes list
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid verification code. Please try again.'
    
    return render_template('verify_totp.html', error=error)

@app.route('/account-settings')
def account_settings():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('account_settings.html', user_data=user)

@app.route('/generate-totp-setup')
def generate_totp_setup():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Generate TOTP secret and store in session temporarily
    secret = pyotp.random_base32()
    session['temp_totp_secret'] = secret
    
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(user.username, issuer_name="Secure Vault")
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    # Convert image to base64 for embedding in HTML
    buffered = BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return jsonify({
        'secret': secret,
        'qr_code': f'data:image/png;base64,{img_str}'
    })

@app.route('/verify-totp-setup', methods=['POST'])
def verify_totp_setup():
    if 'user' not in session or 'temp_totp_secret' not in session:
        return jsonify({'error': 'Setup session expired'}), 401
    
    code = request.form.get('code')
    secret = session['temp_totp_secret']
    
    # Verify the code
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        # Generate recovery codes
        recovery_codes = [secrets.token_hex(8) for _ in range(10)]
        # Store hashed versions in session temporarily
        session['temp_recovery_codes'] = recovery_codes
        session['temp_recovery_codes_hashed'] = [bcrypt.hashpw(code.encode('utf-8'), bcrypt.gensalt()).decode('utf-8') for code in recovery_codes]
        
        return jsonify({
            'success': True,
            'recovery_codes': recovery_codes
        })
    else:
        return jsonify({'success': False})

@app.route('/complete-totp-setup', methods=['POST'])
def complete_totp_setup():
    if 'user' not in session or 'temp_totp_secret' not in session or 'temp_recovery_codes_hashed' not in session:
        return jsonify({'error': 'Setup session expired'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Enable TOTP for the user
    user.totp_secret = session['temp_totp_secret']
    user.totp_enabled = True
    user.recovery_codes = json.dumps(session['temp_recovery_codes_hashed'])
    
    # Save changes
    db.session.commit()
    
    # Clear temporary session data
    session.pop('temp_totp_secret', None)
    session.pop('temp_recovery_codes', None)
    session.pop('temp_recovery_codes_hashed', None)
    
    flash('Two-factor authentication has been enabled for your account.', 'success')
    return jsonify({'success': True})

@app.route('/disable-totp', methods=['POST'])
def disable_totp():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Disable TOTP
    user.totp_enabled = False
    user.totp_secret = None
    user.recovery_codes = None
    
    # Save changes
    db.session.commit()
    
    flash('Two-factor authentication has been disabled for your account.', 'warning')
    return jsonify({'success': True})

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Update user profile
    display_name = request.form.get('display_name')
    email = request.form.get('email')
    
    if display_name and display_name != user.username:
        # Check if username is already taken
        if User.query.filter_by(username=display_name).first() and User.query.filter_by(username=display_name).first().id != user.id:
            flash('Username already taken. Please choose another one.', 'error')
            return redirect(url_for('account_settings'))
        
        user.username = display_name
        session['user'] = display_name
    
    if email and email != user.email:
        # Check if email is already taken
        if User.query.filter_by(email=email).first() and User.query.filter_by(email=email).first().id != user.id:
            flash('Email already taken. Please choose another one.', 'error')
            return redirect(url_for('account_settings'))
        
        user.email = email
    
    db.session.commit()
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('account_settings'))

@app.route('/update-password', methods=['POST'])
def update_password():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validate inputs
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required.', 'error')
        return redirect(url_for('account_settings'))
    
    if not user.check_password(current_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('account_settings'))
    
    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('account_settings'))
    
    if len(new_password) < 8:
        flash('New password must be at least 8 characters long.', 'error')
        return redirect(url_for('account_settings'))
    
    # Update password
    user.set_password(new_password)
    db.session.commit()
    
    flash('Password updated successfully!', 'success')
    return redirect(url_for('account_settings'))

@app.route('/verify-webauthn', methods=['GET', 'POST'])
def verify_webauthn():
    # Check if user is in the middle of authentication
    if 'user_id' not in session or 'awaiting_webauthn' not in session:
        return redirect(url_for('login'))
    
    # WebAuthn verification will be handled via AJAX in the frontend
    return render_template('verify_webauthn.html')

@app.route('/dashboard')
def dashboard():
    # Check if user is logged in
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Check if user needs to complete 2FA
    if 'awaiting_totp' in session or 'awaiting_webauthn' in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', user=session['user'], services=PREDEFINED_SERVICES)

@app.route('/containers')
def list_containers():
    if 'user' not in session:
        return redirect(url_for('login'))
    containers = docker_client.containers.list()
    container_infos = []
    for c in containers:
        ports = c.attrs['NetworkSettings']['Ports']
        mapped = None
        proto = 'http'
        for port, bindings in (ports or {}).items():
            if bindings:
                mapped = bindings[0]['HostPort']
                break
        
        # Check if container has persistent storage
        has_persistent_storage = False
        volume_mounts = []
        if 'Mounts' in c.attrs:
            for mount in c.attrs['Mounts']:
                if mount['Type'] == 'volume':
                    has_persistent_storage = True
                    volume_mounts.append({
                        'source': mount['Source'],
                        'destination': mount['Destination']
                    })
        
        # Determine protocol based on image name
        image_tag = c.image.tags[0] if c.image.tags else ''
        if 'kasmweb/' in image_tag or image_tag.startswith('secure-'):
            proto = 'https'
        
        container_infos.append({
            'id': c.short_id,
            'name': c.name,
            'image': c.image.tags[0] if c.image.tags else c.image.short_id,
            'status': c.status,
            'host_port': mapped,
            'proto': proto,
            'has_persistent_storage': has_persistent_storage,
            'volume_mounts': volume_mounts
        })
    return jsonify(container_infos)

@app.route('/containers/stop', methods=['POST'])
def stop_container():
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    data = request.get_json()
    container_id = data.get('id')
    action = data.get('action', 'kill')  # Default to kill if not specified
    
    try:
        container = docker_client.containers.get(container_id)
        
        # Get container info for logging
        container_name = container.name
        container_image = container.image.tags[0] if container.image.tags else container.image.short_id
        
        if action == 'save':
            # Stop the container gracefully to save state to persistent storage
            container.stop(timeout=10)  # Give it 10 seconds to shut down gracefully
            return jsonify({'success': True, 'message': f'Container {container_name} saved to persistent storage'})
        else:  # kill action
            # Force kill the container without graceful shutdown
            container.kill()
            return jsonify({'success': True, 'message': f'Container {container_name} killed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/launch', methods=['POST'])
def launch_service():
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    data = request.get_json()
    service = data.get('service')
    if service not in PREDEFINED_SERVICES:
        return jsonify({'success': False, 'error': 'Service not found'}), 404
    svc = PREDEFINED_SERVICES[service]
    if 'url' in svc:
        return jsonify({'success': True, 'url': svc['url'], 'https': svc['url'].startswith('https')})
    try:
        # Find a free port from the assigned list
        used_ports = set()
        for c in docker_client.containers.list():
            ports = c.attrs['NetworkSettings']['Ports']
            for port, bindings in (ports or {}).items():
                if bindings:
                    used_ports.add(int(bindings[0]['HostPort']))
        available_ports = [p for p in svc['external_ports'] if p not in used_ports]
        if not available_ports:
            return jsonify({'success': False, 'error': 'No available ports for this service.'})
        host_port = random.choice(available_ports)
        # Create a persistent volume name for this service
        volume_name = f"kasm_{service}_data"
        
        # Check if volume exists, create if it doesn't
        volumes_list = docker_client.volumes.list()
        volume_exists = any(v.name == volume_name for v in volumes_list)
        if not volume_exists:
            docker_client.volumes.create(name=volume_name)
        
        # Determine mount path based on service type
        if 'firefox' in service or 'chrome' in service or 'brave' in service or 'edge' in service or 'tor' in service:
            # For browsers, mount to profile directory
            mount_path = '/config'
        elif 'kali' in service or 'ubuntu' in service or 'alpine' in service or 'debian' in service or 'parrotos' in service:
            # For Linux distros, mount to home directory
            mount_path = '/home/kasm-user'
        elif 'vscode' in service:
            # For VS Code, mount to project directory
            mount_path = '/home/coder/project'
        else:
            # Default mount path
            mount_path = '/data'
        
        # Run container with volume mounted and on secure network
        container = docker_client.containers.run(
            svc['image'],
            detach=True,
            ports={svc.get('internal_port', '6901/tcp'): host_port},
            environment=svc.get('environment', {}),
            volumes={volume_name: {'bind': mount_path, 'mode': 'rw'}},
            network='secure_network'
        )
        # Wait for the container to be ready (port open)
        import socket, time
        ready = False
        max_wait = 30  # seconds
        waited = 0
        while waited < max_wait:
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect(('localhost', int(host_port)))
                ready = True
                s.close()
                break
            except Exception:
                time.sleep(1)
                waited += 1
            finally:
                s.close()
        if not ready:
            return jsonify({'success': False, 'error': 'Container did not become ready in time.'})
        # Determine protocol based on image name
        image_name = svc['image']
        proto = 'https' if image_name.startswith('kasmweb/') or image_name.startswith('secure-') else 'http'
        return jsonify({'success': True, 'message': f"Launched {svc['label']}!", 'host_port': host_port, 'proto': proto})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/add-password', methods=['POST'])
def add_password():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    service = request.form.get('service')
    username = request.form.get('username')
    password = request.form.get('password')
    category = request.form.get('category')
    notes = request.form.get('notes', '')
    
    # Get all URLs from the form
    urls = request.form.getlist('urls[]')
    logo_url = None
    
    # Use the first non-empty URL for the logo if available
    primary_url = next((url for url in urls if url), None)
    
    # If no URLs in the new format, check for the old format
    if not primary_url:
        primary_url = request.form.get('url', '')
        if primary_url:
            urls.append(primary_url)
    
    # If we have a URL, get the favicon
    if primary_url:
        # Extract domain from URL if it has a scheme
        if '://' in primary_url:
            domain = primary_url.split('://', 1)[1].split('/', 1)[0]
        else:
            domain = primary_url.split('/', 1)[0]
        
        # Use Google's favicon API to get the logo
        logo_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=64"
    
    if not (service and username and password and category):
        flash('All fields are required!', 'error')
        return redirect(url_for('password_manager'))
    
    # Create new password entry in database
    new_password = Password(
        service=service,
        username=username,
        password=password,
        category=category,
        notes=notes,
        url=primary_url,  # Store the primary URL in the url field for backward compatibility
        logo_url=logo_url
    )
    db.session.add(new_password)
    db.session.flush()  # Flush to get the new_password.id
    
    # Add all URLs to the WebsiteURL table
    for url in urls:
        if url and url.strip():  # Only add non-empty URLs
            website_url = WebsiteURL(url=url.strip(), password_id=new_password.id)
            db.session.add(website_url)
    
    db.session.commit()
    
    flash('Password added successfully!', 'success')
    return redirect(url_for('password_manager'))

@app.route('/password-manager')
def password_manager():
    if 'user' not in session:
        return redirect(url_for('login'))
    # Get all passwords from database
    passwords = Password.query.order_by(Password.service).all()
    categories = db.session.query(Password.category).distinct().all()
    categories = [c[0] for c in categories if c[0]]
    
    # Get user password generator settings
    settings = get_user_settings(session['user'])
    password_settings = {
        'length': settings.password_length,
        'uppercase': settings.include_uppercase,
        'lowercase': settings.include_lowercase,
        'numbers': settings.include_numbers,
        'symbols': settings.include_symbols,
        'exclude_similar': False,
        'avoid_ambiguous': False
    }
    
    return render_template('password_manager.html', 
                           user=session['user'], 
                           passwords=passwords,
                           categories=categories,
                           password_settings=password_settings)

@app.route('/passwords.json')
def download_passwords():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    export_format = request.args.get('format', 'json')
    passwords = [p.to_dict() for p in Password.query.all()]
    
    if export_format == 'csv':
        # Create CSV in memory
        output = io.StringIO()
        csv_writer = csv.writer(output)
        
        # Write header
        csv_writer.writerow(['Service', 'Username', 'Password', 'URL', 'Category', 'Notes', 'Created'])
        
        # Write data
        for p in passwords:
            csv_writer.writerow([p['service'], p['username'], p['password'], 
                               p.get('url', ''), p.get('category', ''), 
                               p.get('notes', ''), p.get('created_at', '')])
        
        # Create response
        response = Response(output.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename=passwords.csv'
    else:
        # Default JSON export
        temp_file = 'temp_passwords.json'
        with open(temp_file, 'w') as f:
            json.dump(passwords, f, indent=2)
        
        # Send the file and then delete it
        response = send_file(temp_file, as_attachment=True)
        
        # Delete the temporary file after sending
        @response.call_on_close
        def delete_temp_file():
            if os.path.exists(temp_file):
                os.remove(temp_file)
    
    return response

@app.route('/delete-password/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    password = Password.query.get_or_404(password_id)
    db.session.delete(password)
    db.session.commit()
    
    flash('Password deleted successfully!', 'success')
    return redirect(url_for('password_manager'))

@app.route('/file-vault')
def file_vault():
    """File Vault - Secure file storage and management"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get current folder ID from query parameter, default to None (root folder)
    current_folder_id = request.args.get('folder_id', None)
    current_folder = None
    print(f"Raw folder_id from request: {current_folder_id}")
    
    if current_folder_id and current_folder_id != 'null':
        try:
            current_folder_id = int(current_folder_id)
            print(f"Converted folder_id to int: {current_folder_id}")
            current_folder = VaultFolder.query.get_or_404(current_folder_id)
            print(f"Found folder: {current_folder.name}")
        except (ValueError, TypeError) as e:
            print(f"Error processing folder_id: {e}")
            # If folder_id is not a valid integer, default to root
            current_folder_id = None
        # Get files in current folder
        files = VaultFile.query.filter_by(folder_id=current_folder_id).all()
        # Get subfolders in current folder
        folders = VaultFolder.query.filter_by(parent_id=current_folder_id).all()
    else:
        # Get files in root folder (no folder_id)
        files = VaultFile.query.filter_by(folder_id=None).all()
        # Get folders in root
        folders = VaultFolder.query.filter_by(parent_id=None).all()
        print("No folder_id provided or null, using root folder")
    
    # Create breadcrumb navigation
    breadcrumbs = []
    if current_folder:
        # Add current folder
        breadcrumbs.append({'id': current_folder.id, 'name': current_folder.name})
        # Add parent folders
        parent = current_folder.parent
        while parent:
            breadcrumbs.insert(0, {'id': parent.id, 'name': parent.name})
            parent = parent.parent
    
    # Add root folder to breadcrumbs
    breadcrumbs.insert(0, {'id': None, 'name': 'Root'})
    
    # Check if JSON format is requested (for AJAX)
    if request.args.get('format') == 'json':
        print(f"JSON request received for folder_id: {current_folder_id}")
        print(f"Request args: {request.args}")
        print(f"Current folder: {current_folder.name if current_folder else 'Root'}")
        print(f"Files in DB for folder_id {current_folder_id}: {[f.original_filename for f in files]}")
        print(f"File folder_ids: {[f.folder_id for f in files]}")
        
        # Prepare JSON response
        folders_data = [{
            'id': folder.id,
            'name': folder.name,
            'size': folder.size_formatted,
            'date': folder.upload_date.strftime('%Y-%m-%d %H:%M')
        } for folder in folders]
        
        files_data = [{
            'id': file.id,
            'original_filename': file.original_filename,
            'file_type': file.file_type,
            'size': file.size_formatted,
            'date': file.upload_date.strftime('%Y-%m-%d %H:%M')
        } for file in files]
        
        # Print debug information
        print(f"JSON Response - Folder ID: {current_folder_id}")
        print(f"Folders: {len(folders_data)}, Files: {len(files_data)}")
        
        # Print first folder and file for debugging
        if folders_data:
            print(f"First folder: {folders_data[0]}")
        if files_data:
            print(f"First file: {files_data[0]}")
        
        response_data = {
            'folders': folders_data,
            'files': files_data,
            'current_folder': {
                'id': current_folder.id if current_folder else None,
                'name': current_folder.name if current_folder else 'Root'
            }
        }
        
        print(f"Sending JSON response: {response_data}")
        print(f"Response type: {type(response_data)}")
        print(f"Response keys: {response_data.keys()}")
        print(f"Folders type: {type(response_data['folders'])}")
        print(f"Files type: {type(response_data['files'])}")
        print(f"Current folder type: {type(response_data['current_folder'])}")
        
        
        return jsonify(response_data)
    
    # Otherwise return HTML template
    return render_template('file_vault.html', 
                           user=session['user'], 
                           files=files, 
                           folders=folders, 
                           current_folder=current_folder,
                           breadcrumbs=breadcrumbs)

@app.route('/upload-file', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get current folder ID from form
    folder_id = request.form.get('folder_id')
    folder_id = int(folder_id) if folder_id and folder_id != 'null' else None
    
    # Check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('file_vault', folder_id=folder_id))
    
    file = request.files['file']
    description = request.form.get('description', '')
    
    # If user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('file_vault', folder_id=folder_id))
    
    if file:
        # Secure the filename
        original_filename = secure_filename(file.filename)
        
        # Read file data
        file_data = file.read()
        file_size = len(file_data)
        
        # Get file type
        file_type = file.content_type or 'application/octet-stream'
        
        # Encrypt the file data
        encrypted_data, iv = encrypt_file(file_data)
        
        # Generate a unique filename
        filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{original_filename}"
        
        # Save to database
        new_file = VaultFile(
            filename=filename,
            original_filename=original_filename,
            file_type=file_type,
            file_size=file_size,
            encrypted_data=encrypted_data,
            iv=iv,
            folder_id=folder_id
        )
        db.session.add(new_file)
        db.session.commit()
        
        flash('File uploaded and encrypted successfully!', 'success')
        return redirect(url_for('file_vault', folder_id=folder_id))

@app.route('/create-folder', methods=['POST'])
def create_folder():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get folder name and parent folder ID
    folder_name = request.form.get('folder_name')
    parent_id = request.form.get('parent_id')
    parent_id = int(parent_id) if parent_id and parent_id != 'null' else None
    
    if not folder_name:
        flash('Folder name is required', 'error')
        return redirect(url_for('file_vault', folder_id=parent_id))
    
    # Create new folder
    new_folder = VaultFolder(
        name=folder_name,
        parent_id=parent_id
    )
    db.session.add(new_folder)
    db.session.commit()
    
    flash(f'Folder "{folder_name}" created successfully!', 'success')
    return redirect(url_for('file_vault', folder_id=parent_id))

@app.route('/upload-folder', methods=['POST'])
def upload_folder():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get current folder ID from form
    parent_id = request.form.get('folder_id')
    parent_id = int(parent_id) if parent_id and parent_id != 'null' else None
    
    # Check if the post request has files
    if 'files[]' not in request.files:
        flash('No files uploaded', 'error')
        return redirect(url_for('file_vault', folder_id=parent_id))
    
    files = request.files.getlist('files[]')
    folder_paths = request.form.getlist('folder_paths[]')
    
    if not files or len(files) == 0:
        flash('No files selected', 'error')
        return redirect(url_for('file_vault', folder_id=parent_id))
    
    # Process folder structure and files
    folder_map = {None: parent_id}  # Maps relative folder paths to DB folder IDs
    
    for i, file in enumerate(files):
        if file.filename == '':
            continue
        # Get folder path for this file
        folder_path = folder_paths[i] if i < len(folder_paths) else ''
        # Create folder structure if needed
        current_parent_id = parent_id
        if folder_path:
            path_parts = folder_path.split('/')
            current_path = ''
            for part in path_parts:
                if not part:
                    continue
                current_path = current_path + '/' + part if current_path else part
                if current_path in folder_map:
                    current_parent_id = folder_map[current_path]
                else:
                    new_folder = VaultFolder(
                        name=part,
                        parent_id=current_parent_id
                    )
                    db.session.add(new_folder)
                    db.session.flush()
                    folder_map[current_path] = new_folder.id
                    current_parent_id = new_folder.id
        original_filename = secure_filename(file.filename.split('/')[-1])
        file_data = file.read()
        file_size = len(file_data)
        file_type = file.content_type or 'application/octet-stream'
        encrypted_data, iv = encrypt_file(file_data)
        filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{original_filename}"
        # Debug: print file and folder assignment
        print(f"Uploading file: {original_filename} to folder_id: {current_parent_id} (folder_path: '{folder_path}')")
        new_file = VaultFile(
            filename=filename,
            original_filename=original_filename,
            file_type=file_type,
            file_size=file_size,
            encrypted_data=encrypted_data,
            iv=iv,
            folder_id=current_parent_id
        )
        db.session.add(new_file)
    # Debug: print folder map after upload
    print(f"Folder map after upload: {folder_map}")
    db.session.commit()
    flash('Folder uploaded and encrypted successfully!', 'success')
    return redirect(url_for('file_vault', folder_id=parent_id))

@app.route('/download-file/<int:file_id>')
def download_file(file_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get the file from database
    file = VaultFile.query.get_or_404(file_id)
    
    # Decrypt the file data
    decrypted_data = decrypt_file(file.encrypted_data, file.iv)
    
    # Create a BytesIO object for the decrypted data
    file_data = io.BytesIO(decrypted_data)
    
    # Return the file for download
    return send_file(
        file_data,
        mimetype=file.file_type,
        as_attachment=True,
        download_name=file.original_filename
    )

@app.route('/download-folder/<int:folder_id>')
def download_folder(folder_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get the folder from database
    folder = VaultFolder.query.get_or_404(folder_id)
    
    # Create a BytesIO object for the zip file
    zip_data = io.BytesIO()
    
    # Import zipfile module
    import zipfile
    
    # Create a zip file
    with zipfile.ZipFile(zip_data, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Function to recursively add files and folders to zip
        def add_folder_to_zip(current_folder, path=''):
            # Add files in current folder
            for file in current_folder.files:
                # Decrypt file data
                decrypted_data = decrypt_file(file.encrypted_data, file.iv)
                # Add file to zip
                file_path = os.path.join(path, file.original_filename)
                zipf.writestr(file_path, decrypted_data)
            
            # Add subfolders recursively
            for subfolder in current_folder.subfolders:
                subfolder_path = os.path.join(path, subfolder.name)
                add_folder_to_zip(subfolder, subfolder_path)
        
        # Start adding files and folders
        add_folder_to_zip(folder, folder.name)
    
    # Reset file pointer to beginning
    zip_data.seek(0)
    
    # Return the zip file for download
    return send_file(
        zip_data,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"{folder.name}.zip"
    )

@app.route('/delete-file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    file = VaultFile.query.get_or_404(file_id)
    folder_id = file.folder_id
    db.session.delete(file)
    db.session.commit()
    
    flash('File deleted successfully!', 'success')
    return redirect(url_for('file_vault', folder_id=folder_id))

@app.route('/delete-folder/<int:folder_id>', methods=['POST'])
def delete_folder(folder_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    folder = VaultFolder.query.get_or_404(folder_id)
    parent_id = folder.parent_id
    
    # Delete the folder (cascade will delete all files and subfolders)
    db.session.delete(folder)
    db.session.commit()
    
    flash('Folder and all its contents deleted successfully!', 'success')
    return redirect(url_for('file_vault', folder_id=parent_id))

@app.route('/api/launch-with-url', methods=['POST'])
def launch_service_with_url():
    data = request.get_json()
    service = data.get('service')
    url = data.get('url')
    
    # Validate inputs
    if not service or not url:
        return jsonify({'success': False, 'error': 'Service and URL are required'}), 400
    
    if service not in PREDEFINED_SERVICES:
        return jsonify({'success': False, 'error': 'Service not found'}), 404
    
    # Only allow certain services (browsers) to be launched with a URL
    allowed_services = ['chrome', 'firefox', 'brave', 'edge', 'tor']
    if service not in allowed_services:
        return jsonify({'success': False, 'error': 'This service does not support direct URL launching'}), 400
    
    # Validate URL format
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("Invalid URL format")
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid URL format'}), 400
    
    svc = PREDEFINED_SERVICES[service]
    try:
        # Find a free port from the assigned list
        used_ports = set()
        for c in docker_client.containers.list():
            ports = c.attrs['NetworkSettings']['Ports']
            for port, bindings in (ports or {}).items():
                if bindings:
                    used_ports.add(int(bindings[0]['HostPort']))
        available_ports = [p for p in svc['external_ports'] if p not in used_ports]
        if not available_ports:
            return jsonify({'success': False, 'error': 'No available ports for this service.'})
        host_port = random.choice(available_ports)
        
        # Create a persistent volume name for this service
        volume_name = f"kasm_{service}_data"
        
        # Check if volume exists, create if it doesn't
        volumes_list = docker_client.volumes.list()
        volume_exists = any(v.name == volume_name for v in volumes_list)
        if not volume_exists:
            docker_client.volumes.create(name=volume_name)
        
        # Determine mount path based on service type
        if 'firefox' in service or 'chrome' in service or 'brave' in service or 'edge' in service or 'tor' in service:
            # For browsers, mount to profile directory
            mount_path = '/config'
        else:
            # Default mount path
            mount_path = '/data'
        
        # Create environment variables with the URL to open
        env_vars = svc.get('environment', {}).copy()
        env_vars['KASM_URL'] = url
        
        # Run container with volume mounted, URL environment variable, and on secure network
        container = docker_client.containers.run(
            svc['image'],
            detach=True,
            ports={svc.get('internal_port', '6901/tcp'): host_port},
            environment=env_vars,
            volumes={volume_name: {'bind': mount_path, 'mode': 'rw'}},
            network='secure_network'
        )
        
        # Wait for the container to be ready (port open)
        import socket, time
        ready = False
        max_wait = 30  # seconds
        waited = 0
        while waited < max_wait:
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect(('localhost', int(host_port)))
                ready = True
                s.close()
                break
            except Exception:
                time.sleep(1)
                waited += 1
            finally:
                s.close()
        
        if not ready:
            return jsonify({'success': False, 'error': 'Container did not become ready in time.'})
        
        # Determine protocol based on image name
        image_name = svc['image']
        proto = 'https' if image_name.startswith('kasmweb/') or image_name.startswith('secure-') else 'http'
        return jsonify({
            'success': True, 
            'message': f"Launched {svc['label']} with URL: {url}", 
            'host_port': host_port, 
            'proto': proto
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/view_password/<int:id>')
def view_password(id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    password = Password.query.get_or_404(id)
    return render_template('view_password.html', user=session['user'], password=password)

@app.route('/edit_password/<int:id>', methods=['GET', 'POST'])
def edit_password(id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    password = Password.query.get_or_404(id)
    
    if request.method == 'POST':
        # Get form data
        service = request.form.get('service')
        username = request.form.get('username')
        new_password = request.form.get('password')
        category = request.form.get('category')
        notes = request.form.get('notes', '')
        
        # Get all URLs from the form
        urls = request.form.getlist('urls[]')
        
        if not (service and username and new_password and category):
            flash('All required fields must be filled!', 'error')
            return render_template('edit_password.html', user=session['user'], password=password)
        
        # Update password
        password.service = service
        password.username = username
        password.password = new_password
        password.category = category
        password.notes = notes
        
        # Use the first non-empty URL as the primary URL
        primary_url = next((url for url in urls if url), None) or ''
        
        # Update URL and logo_url if primary URL has changed
        if primary_url != password.url:
            password.url = primary_url
            
            # If URL is provided, get the favicon using Google's favicon API
            if primary_url:
                # Extract domain from URL if it has a scheme
                if '://' in primary_url:
                    domain = primary_url.split('://', 1)[1].split('/', 1)[0]
                else:
                    domain = primary_url.split('/', 1)[0]
                
                # Use Google's favicon API to get the logo
                password.logo_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=64"
            else:
                password.logo_url = None
        
        # Delete existing website URLs
        WebsiteURL.query.filter_by(password_id=password.id).delete()
        
        # Add all URLs to the WebsiteURL table
        for url in urls:
            if url and url.strip():  # Only add non-empty URLs
                website_url = WebsiteURL(url=url.strip(), password_id=password.id)
                db.session.add(website_url)
        
        password.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash('Password updated successfully!', 'success')
        return redirect(url_for('view_password', id=id))
    
    return render_template('edit_password.html', user=session['user'], password=password)

@app.route('/terminal')
def terminal():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('terminal.html', user=session['user'])

# Route removed to fix duplicate endpoint error
# Now using /account-settings instead

@app.route('/preferences')
def preferences():
    if 'user' not in session:
        return redirect(url_for('login'))
    settings = get_user_settings(session['user'])
    return render_template('preferences.html', user=session['user'], settings=settings)

@app.route('/help_support')
def help_support():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('help_support.html', user=session['user'])

# Terminal process management
terminal_processes = {}

@sock.route('/terminal/ws')
def terminal_ws(ws):
    import socket as pysocket
    import time
    session_id = f"term_{random.randint(1000, 9999)}"
    container_name = f"terminal_{session_id}"
    try:
        # Ensure Ubuntu image is available
        try:
            docker_client.images.get('ubuntu:latest')
        except docker.errors.ImageNotFound:
            docker_client.images.pull('ubuntu:latest')

        # Start the container with a running bash shell
        container = docker_client.containers.run(
            'ubuntu:latest',
            command="bash",
            detach=True,
            tty=True,
            stdin_open=True,
            remove=True,
            name=container_name,
            network="secure_network",
            environment={
                "TERM": "xterm-256color",
                "DEBIAN_FRONTEND": "noninteractive"
            }
        )

        # Attach to the container's TTY using a socket
        sock_obj = container.attach_socket(params={
            'stdin': 1, 'stdout': 1, 'stderr': 1, 'stream': 1, 'logs': 1
        })
        sock_obj._sock.setblocking(True)

        # Send initial message
        if ws.connected:
            ws.send(json.dumps({
                'type': 'output',
                'data': '\r\nConnected to Ubuntu terminal.\r\n'
            }))

        # Thread to read from container and send to WebSocket
        def read_from_container():
            try:
                while ws.connected:
                    data = sock_obj._sock.recv(4096)
                    if not data:
                        break
                    ws.send(json.dumps({'type': 'output', 'data': data.decode('utf-8', errors='replace')}))
            except Exception as e:
                if ws.connected:
                    ws.send(json.dumps({'type': 'output', 'data': f'\r\n[Error reading from container: {e}]\r\n'}))

        t = threading.Thread(target=read_from_container, daemon=True)
        t.start()

        # Main WebSocket loop: send input to container
        while ws.connected:
            message = ws.receive()
            if message:
                try:
                    data = json.loads(message)
                    if data['type'] == 'input':
                        try:
                            sock_obj._sock.send(data['data'].encode('utf-8'))
                        except Exception as e:
                            ws.send(json.dumps({'type': 'output', 'data': f'\r\n[Input error: {e}]\r\n'}))
                    elif data['type'] == 'resize':
                        # Optionally handle resize (not implemented here)
                        pass
                    elif data['type'] == 'restart':
                        ws.send(json.dumps({'type': 'output', 'data': '\r\nRestart not supported in this mode.\r\n'}))
                except Exception as e:
                    ws.send(json.dumps({'type': 'output', 'data': f'\r\n[Error: {e}]\r\n'}))
    except Exception as e:
        if ws.connected:
            ws.send(json.dumps({'type': 'output', 'data': f'\r\n[Terminal error: {e}]\r\n'}))
    finally:
        try:
            container.stop()
            container.remove()
        except:
            pass

@app.route('/update-password-settings', methods=['POST'])
def update_password_settings():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get form data
    password_length = request.form.get('password-length', type=int)
    admin_password = request.form.get('admin-password')

    # Update settings in the database or configuration file
    if password_length:
        app.config['DEFAULT_PASSWORD_LENGTH'] = password_length
    if admin_password:
        app.config['ADMIN_PASSWORD'] = admin_password

    flash('Password settings updated successfully!', 'success')
    return redirect(url_for('preferences'))

@app.route('/api/user-settings', methods=['GET'])
def api_get_user_settings():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    settings = get_user_settings(session['user'])
    return jsonify(settings.to_dict())

@app.route('/api/update-settings', methods=['POST'])
def api_update_settings():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    settings = get_user_settings(session['user'])
    data = request.json or request.form
    # Update all fields if present
    for field in settings.to_dict().keys():
        if field in data:
            value = data[field]
            # Convert types for booleans and ints
            if getattr(UserSettings, field).type.python_type is bool:
                value = value in [True, 'true', 'True', 1, '1', 'on']
            elif getattr(UserSettings, field).type.python_type is int:
                try:
                    value = int(value)
                except Exception:
                    continue
            setattr(settings, field, value)
    db.session.commit()
    return jsonify({'success': True, 'settings': settings.to_dict()})

@app.route('/api/reset-settings', methods=['POST'])
def api_reset_settings():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    settings = get_user_settings(session['user'])
    settings.reset_to_defaults()
    db.session.commit()
    return jsonify({'success': True, 'settings': settings.to_dict()})

@app.route('/api/passwords', methods=['GET'])
def api_passwords():
    """API endpoint to get passwords for the browser extension"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get all passwords from database
    passwords = Password.query.order_by(Password.service).all()
    
    # Convert passwords to dictionary with decrypted passwords
    password_list = []
    for p in passwords:
        password_dict = p.to_dict()
        password_list.append(password_dict)
    
    return jsonify(password_list)

if __name__ == '__main__':
    app.run(debug=True)
