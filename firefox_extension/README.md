# Kasm Secure Browser Launcher & Password Manager

A comprehensive Firefox extension that enhances your browsing security by allowing you to open links in isolated containers and providing secure password management with autofill capabilities.

## Features

### Secure Browser Launcher
- Right-click on any link to open it in a secure Chrome container running in Kasm Workspace
- Isolates browsing activity from your main browser for enhanced privacy
- Leverages Kasm Workspace's containerization for robust security

### Password Manager
- Securely store and manage your passwords
- Auto-detect login forms on websites
- One-click autofill for usernames and passwords
- Special handling for popular sites like Google and Apple
- Search and filter passwords by website or username
- Copy username/password to clipboard with a single click
- Toggle password visibility for easy verification

## Installation

### Temporary Installation (for Development)

1. Open Firefox and navigate to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on..."
4. Navigate to the `firefox_extension` folder and select the `manifest.json` file

### Permanent Installation

1. Zip the contents of the `firefox_extension` folder
2. Rename the zip file to `kasm_secure_browser.xpi`
3. Open Firefox and navigate to `about:addons`
4. Click the gear icon and select "Install Add-on From File..."
5. Select the `kasm_secure_browser.xpi` file

## Usage

1. Make sure your Kasm Workspace is running
2. Right-click on any link in Firefox
3. Select "Open in Secure Browser" from the context menu
4. The link will open in a Chrome container within Kasm Workspace
5. A new tab will automatically open with the secure container interface

## Requirements

- Firefox browser
- Kasm Workspace running on localhost:5000
- Chrome container configured in Kasm Workspace

## Troubleshooting

If you encounter issues:

1. Ensure Kasm Workspace is running
2. Check that the Chrome container is properly configured
3. Look for error notifications from the extension

## Privacy & Security

This extension communicates only with your local Kasm Workspace instance. No data is sent to external servers.