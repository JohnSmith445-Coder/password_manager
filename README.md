# Password Workspace (Flask)

A comprehensive Flask-based alternative to Kasm Workspace with enhanced security features. This project provides a modern, clean UI with animations, secure file storage, password management, and a Firefox extension for secure browsing.

## Features

### Core Features
- Modern, responsive UI with smooth animations and transitions
- Secure file vault with encryption for file storage
- Password manager with secure storage and autofill capabilities
- Firefox extension for secure browsing in isolated containers
- Interactive workspace management

### Technical Features
- Flask backend with SQLAlchemy for database management
- Cryptographic security for sensitive data
- Docker integration for container management
- WebAuthn support for passwordless authentication
- TOTP-based two-factor authentication
- Modern JavaScript with smooth animations and transitions
- Responsive design that works on various devices

## Getting Started

### Prerequisites
- Python 3.8 or higher
- Docker (for container features)
- Firefox (for the extension)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/kasm-workspace.git
   cd kasm-workspace
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the app:
   ```bash
   python app.py
   ```

4. Open your browser at http://127.0.0.1:5000/

### Firefox Extension Installation

1. Open Firefox and navigate to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on..."
4. Navigate to the `firefox_extension` folder and select the `manifest.json` file

For permanent installation, see the extension's README in the `firefox_extension` directory.

## Project Structure

### Backend
- `app.py`: Main Flask application
- `models.py`: Database models
- `utils/`: Utility functions for encryption, authentication, etc.

### Frontend
- `templates/`: HTML templates for all pages
- `static/`: Static assets
  - `css/`: Stylesheets with modern design
  - `js/`: JavaScript for interactivity and animations
  - `images/`: Icons and images

### Firefox Extension
- `firefox_extension/`: Complete Firefox extension for secure browsing
  - `manifest.json`: Extension configuration
  - `background.js`: Background script for context menu and API calls
  - `content.js`: Content script for page interaction and autofill
  - `popup.js`: Script for the extension popup
  - `popup.html`: Extension popup interface
  - `popup.css`: Styling for the popup

## Security Features

- **File Encryption**: All files in the vault are encrypted before storage
- **Password Security**: Passwords are securely stored with strong encryption
- **Container Isolation**: Browser sessions run in isolated containers
- **Two-Factor Authentication**: Optional TOTP-based 2FA
- **WebAuthn Support**: Passwordless authentication with security keys

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

© 2023 Kasm Workspace Alternative
