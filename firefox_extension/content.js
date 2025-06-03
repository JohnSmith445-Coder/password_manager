// Content script for Kasm Password Manager autofill functionality

// Global variables
let formDetected = false;
let loginForm = null;
let usernameField = null;
let passwordField = null;
let autofillButton = null;
let autofillOverlay = null;

// Initialize when the page loads
document.addEventListener('DOMContentLoaded', () => {
    // Delay the form detection to ensure the page is fully loaded
    setTimeout(detectForms, 1000);
});

// Listen for DOM changes to detect dynamically loaded forms
const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
            // Check if any added nodes might contain a form
            detectForms();
            break;
        }
    }
});

// Start observing the document with the configured parameters
observer.observe(document.documentElement, { childList: true, subtree: true });

// Detect login forms on the page
function detectForms() {
    // Reset form detection state
    formDetected = false;
    usernameField = null;
    passwordField = null;
    loginForm = null;
    
    console.log('Detecting login forms on the page');
    
    // Special handling for Google login forms
    if (window.location.hostname.includes('google.com')) {
        console.log('Detected Google domain, using Google-specific selectors');
        
        // Google email input field (first step)
        const googleEmailInput = document.querySelector('input[type="email"][autocomplete="username"], input#identifierId, input[name="identifier"]');
        
        // Google password input field (second step)
        const googlePasswordInput = document.querySelector('input[type="password"][autocomplete="current-password"], input[name="password"]');
        
        if (googleEmailInput) {
            console.log('Found Google email input field');
            usernameField = googleEmailInput;
            loginForm = googleEmailInput.closest('form, div[role="presentation"], div.lCoei, div.Wxwduf');
            formDetected = true;
        }
        
        if (googlePasswordInput) {
            console.log('Found Google password input field');
            passwordField = googlePasswordInput;
            loginForm = googlePasswordInput.closest('form, div[role="presentation"], div.lCoei, div.Wxwduf');
            formDetected = true;
        }
        
        if (formDetected) {
            console.log('Google login form detected:', {
                hasUsernameField: !!usernameField,
                hasPasswordField: !!passwordField,
                loginFormTag: loginForm ? loginForm.tagName : 'none'
            });
            createAutofillButton();
            return;
        }
    }
    
    // Special handling for Apple login forms
    if (window.location.hostname.includes('apple.com')) {
        console.log('Detected Apple domain, using Apple-specific selectors');
        
        // Apple ID input field (first step)
        const appleIdInput = document.querySelector('input#account_name_text_field, input[name="appleId"], input[name="accountName"]');
        
        // Apple password input field (second step)
        const applePasswordInput = document.querySelector('input#password_text_field, input[name="password"], input[type="password"]');
        
        if (appleIdInput) {
            console.log('Found Apple ID input field');
            usernameField = appleIdInput;
            loginForm = appleIdInput.closest('form, div.signin-container, div.idms-flow-container');
            formDetected = true;
        }
        
        if (applePasswordInput) {
            console.log('Found Apple password input field');
            passwordField = applePasswordInput;
            loginForm = applePasswordInput.closest('form, div.signin-container, div.idms-flow-container');
            formDetected = true;
        }
        
        if (formDetected) {
            console.log('Apple login form detected:', {
                hasUsernameField: !!usernameField,
                hasPasswordField: !!passwordField,
                loginFormTag: loginForm ? loginForm.tagName : 'none'
            });
            createAutofillButton();
            return;
        }
    }
    
    // Continue with standard form detection for other sites
    // Look for password fields
    const passwordFields = document.querySelectorAll('input[type="password"]');
    
    // If no password fields found, look for email/username fields (for multi-step logins)
    if (passwordFields.length === 0) {
        const emailFields = document.querySelectorAll('input[type="email"], input[name="email"], input[name="username"], input[autocomplete="email"], input[autocomplete="username"]');
        
        if (emailFields.length > 0) {
            // Use the first email/username field found
            usernameField = emailFields[0];
            
            // Find the form containing this field
            loginForm = usernameField.closest('form') || usernameField.closest('div, section, article');
            
            if (loginForm) {
                formDetected = true;
                console.log('Email/username-only form detected (multi-step login)');
                createAutofillButton();
            }
        }
        
        return;
    }
    
    // Process each password field found
    for (const passwordField of passwordFields) {
        // Find the form containing this password field
        const form = passwordField.closest('form') || passwordField.closest('div, section, article');
        
        if (!form) continue;
        
        // Set the password field and form
        this.passwordField = passwordField;
        loginForm = form;
        
        // Try to find a username field in the same form
        // First, look for common username field identifiers
        const usernameSelectors = [
            'input[type="email"]',
            'input[type="text"][name="email"]',
            'input[type="text"][name*="user"]',
            'input[type="text"][name*="login"]',
            'input[type="text"][name*="id"]',
            'input[type="text"][autocomplete="email"]',
            'input[type="text"][autocomplete="username"]',
            'input[name="username"]',
            'input[name="email"]'
        ];
        
        for (const selector of usernameSelectors) {
            const potentialUsernameField = form.querySelector(selector);
            if (potentialUsernameField) {
                usernameField = potentialUsernameField;
                break;
            }
        }
        
        // If no username field found by selectors, look for text inputs that come before the password field
        if (!usernameField) {
            const allInputs = Array.from(form.querySelectorAll('input[type="text"], input[type="email"]'));
            const passwordIndex = allInputs.indexOf(passwordField);
            
            if (passwordIndex > 0) {
                // Use the input field that comes right before the password field
                usernameField = allInputs[passwordIndex - 1];
            }
        }
        
        // Form detected, create the autofill button
        formDetected = true;
        console.log('Login form detected:', {
            hasUsernameField: !!usernameField,
            hasPasswordField: true,
            loginFormTag: loginForm.tagName
        });
        createAutofillButton();
        
        // We only need to process one form, so break after the first valid one
        break;
    }
    
    // If no form with password field found, but we have a password field,
    // handle it as a password-only form (second step of multi-step login)
    if (!formDetected && passwordFields.length > 0) {
        passwordField = passwordFields[0];
        loginForm = passwordField.closest('div, section, article');
        
        if (loginForm) {
            formDetected = true;
            console.log('Password-only form detected (multi-step login)');
            createAutofillButton();
        }
    }
}

// Create the autofill button
function createAutofillButton() {
    // Create the button element
    autofillButton = document.createElement('div');
    autofillButton.className = 'kasm-autofill-button';
    autofillButton.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
            <path fill="currentColor" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
        </svg>
    `;
    
    // Add styles to the button
    const style = document.createElement('style');
    style.textContent = `
        .kasm-autofill-button {
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 50px;
            height: 50px;
            border-radius: 25px;
            background-color: #4285F4;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
            z-index: 9999;
            transition: transform 0.2s, background-color 0.2s;
        }
        
        .kasm-autofill-button:hover {
            transform: scale(1.1);
            background-color: #3367d6;
        }
        
        .kasm-autofill-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
        }
        
        .kasm-autofill-popup {
            background-color: #202124;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            width: 350px;
            max-width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            color: #e8eaed;
        }
        
        .kasm-autofill-header {
            padding: 16px;
            border-bottom: 1px solid #5f6368;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .kasm-autofill-title {
            font-size: 18px;
            font-weight: bold;
            color: #4285F4;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .kasm-autofill-close {
            background: none;
            border: none;
            color: #9aa0a6;
            cursor: pointer;
            font-size: 20px;
            padding: 0;
        }
        
        .kasm-autofill-content {
            padding: 16px;
        }
        
        .kasm-autofill-search {
            position: relative;
            margin-bottom: 16px;
        }
        
        .kasm-autofill-search input {
            width: 100%;
            padding: 8px 16px 8px 36px;
            border-radius: 20px;
            border: 1px solid #5f6368;
            background-color: #303134;
            color: #e8eaed;
            font-size: 14px;
        }
        
        .kasm-autofill-search i {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: #9aa0a6;
        }
        
        .kasm-autofill-list {
            max-height: 300px;
            overflow-y: auto;
        }
        
        .kasm-autofill-item {
            padding: 12px;
            border-bottom: 1px solid #5f6368;
            cursor: pointer;
            transition: background-color 0.2s;
            display: flex;
            align-items: center;
        }
        
        .kasm-autofill-item:last-child {
            border-bottom: none;
        }
        
        .kasm-autofill-item:hover {
            background-color: #303134;
        }
        
        .kasm-autofill-item-icon {
            width: 24px;
            height: 24px;
            margin-right: 12px;
            background-color: #303134;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #4285F4;
        }
        
        .kasm-autofill-item-info {
            flex: 1;
        }
        
        .kasm-autofill-item-service {
            font-weight: bold;
            margin-bottom: 4px;
        }
        
        .kasm-autofill-item-username {
            font-size: 12px;
            color: #9aa0a6;
        }
        
        .kasm-autofill-empty {
            padding: 24px 16px;
            text-align: center;
            color: #9aa0a6;
        }
    `;
    
    // Add the style to the document
    document.head.appendChild(style);
    
    // Add the button to the document
    document.body.appendChild(autofillButton);
    
    // Add event listener to the button
    autofillButton.addEventListener('click', showAutofillOverlay);
}

// Show the autofill overlay
function showAutofillOverlay() {
    // Create the overlay element
    autofillOverlay = document.createElement('div');
    autofillOverlay.className = 'kasm-autofill-overlay';
    
    // Get the current URL's domain
    const currentDomain = window.location.hostname;
    
    // Create the popup content
    autofillOverlay.innerHTML = `
        <div class="kasm-autofill-popup">
            <div class="kasm-autofill-header">
                <div class="kasm-autofill-title">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20">
                        <path fill="currentColor" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
                    </svg>
                    Kasm Password Manager
                </div>
                <button class="kasm-autofill-close">×</button>
            </div>
            <div class="kasm-autofill-content">
                <div class="kasm-autofill-search">
                    <i class="fas fa-search"></i>
                    <input type="text" placeholder="Search passwords..." id="kasm-autofill-search-input">
                </div>
                <div class="kasm-autofill-list" id="kasm-autofill-list">
                    <div class="kasm-autofill-empty">
                        <i class="fas fa-spinner fa-spin"></i>
                        <p>Loading passwords...</p>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Add the overlay to the document
    document.body.appendChild(autofillOverlay);
    
    // Add event listener to the close button
    const closeButton = autofillOverlay.querySelector('.kasm-autofill-close');
    closeButton.addEventListener('click', hideAutofillOverlay);
    
    // Add event listener to the search input
    const searchInput = autofillOverlay.querySelector('#kasm-autofill-search-input');
    searchInput.addEventListener('input', filterAutofillList);
    
    // Prevent clicks on the popup from closing the overlay
    const popup = autofillOverlay.querySelector('.kasm-autofill-popup');
    popup.addEventListener('click', (event) => {
        event.stopPropagation();
    });
    
    // Close the overlay when clicking outside the popup
    autofillOverlay.addEventListener('click', hideAutofillOverlay);
    
    // Request passwords from the background script
    browser.runtime.sendMessage({ action: 'getPasswords' })
        .then(response => {
            if (response.success) {
                renderAutofillList(response.passwords, currentDomain);
            } else {
                showAutofillError(response.error || 'Failed to load passwords');
            }
        })
        .catch(error => {
            console.error('Error getting passwords:', error);
            showAutofillError('Failed to communicate with the extension');
        });
}

// Hide the autofill overlay
function hideAutofillOverlay() {
    if (autofillOverlay) {
        document.body.removeChild(autofillOverlay);
        autofillOverlay = null;
    }
}

// Render the autofill list
function renderAutofillList(passwords, currentDomain) {
    const listElement = document.getElementById('kasm-autofill-list');
    
    // Clear the list
    listElement.innerHTML = '';
    
    if (passwords.length === 0) {
        listElement.innerHTML = `
            <div class="kasm-autofill-empty">
                <p>No passwords found</p>
            </div>
        `;
        return;
    }
    
    // Sort passwords by relevance to the current domain
    passwords.sort((a, b) => {
        const aRelevance = isRelevantToCurrentDomain(a, currentDomain) ? 1 : 0;
        const bRelevance = isRelevantToCurrentDomain(b, currentDomain) ? 1 : 0;
        
        // If both or neither are relevant to the current domain, sort by service name
        if (aRelevance === bRelevance) {
            return a.service.localeCompare(b.service);
        }
        
        // Otherwise, sort by relevance (higher relevance first)
        return bRelevance - aRelevance;
    });
    
    // Create an item for each password
    passwords.forEach(password => {
        const item = document.createElement('div');
        item.className = 'kasm-autofill-item';
        
        // Highlight items relevant to the current domain
        if (isRelevantToCurrentDomain(password, currentDomain)) {
            item.style.backgroundColor = 'rgba(66, 133, 244, 0.1)';
            item.style.borderLeft = '3px solid #4285F4';
        }
        
        item.innerHTML = `
            <div class="kasm-autofill-item-icon">
                <i class="fas fa-key"></i>
            </div>
            <div class="kasm-autofill-item-info">
                <div class="kasm-autofill-item-service">${escapeHtml(password.service)}</div>
                <div class="kasm-autofill-item-username">${escapeHtml(password.username)}</div>
            </div>
        `;
        
        // Add event listener to autofill the form
        item.addEventListener('click', () => {
            autofillForm(password);
            hideAutofillOverlay();
        });
        
        // Add the item to the list
        listElement.appendChild(item);
    });
}

// Show an error in the autofill list
function showAutofillError(message) {
    const listElement = document.getElementById('kasm-autofill-list');
    
    listElement.innerHTML = `
        <div class="kasm-autofill-empty">
            <p>${escapeHtml(message)}</p>
        </div>
    `;
}

// Filter the autofill list based on search input
function filterAutofillList() {
    const searchInput = document.getElementById('kasm-autofill-search-input');
    const searchTerm = searchInput.value.toLowerCase();
    
    // Request filtered passwords from the background script
    browser.runtime.sendMessage({ 
        action: 'getPasswords', 
        searchTerm: searchTerm 
    })
    .then(response => {
        if (response.success) {
            renderAutofillList(response.passwords, window.location.hostname);
        }
    })
    .catch(error => {
        console.error('Error filtering passwords:', error);
    });
}

// Autofill the form with the selected password
function autofillForm(password) {
    if (!loginForm) {
        console.error('No login form found to autofill');
        return;
    }
    
    console.log('Autofilling form with type:', 
              usernameField && passwordField ? 'username+password' : 
              usernameField ? 'username-only' : 'password-only');
    
    // Handle case where we have both username and password fields
    if (usernameField && passwordField) {
        console.log('Filling both username and password fields');
        
        // Fill the username field
        usernameField.value = password.username;
        usernameField.dispatchEvent(new Event('input', { bubbles: true }));
        usernameField.dispatchEvent(new Event('change', { bubbles: true }));
        
        // For Google specifically, trigger additional events
        if (window.location.hostname.includes('google.com')) {
            usernameField.dispatchEvent(new Event('keyup', { bubbles: true }));
            usernameField.dispatchEvent(new Event('blur', { bubbles: true }));
        }
        
        // Fill the password field
        passwordField.value = password.password;
        passwordField.dispatchEvent(new Event('input', { bubbles: true }));
        passwordField.dispatchEvent(new Event('change', { bubbles: true }));
        
        // For Google specifically, trigger additional events
        if (window.location.hostname.includes('google.com')) {
            passwordField.dispatchEvent(new Event('keyup', { bubbles: true }));
            passwordField.dispatchEvent(new Event('blur', { bubbles: true }));
        }
        
        // Try to find and click the submit button if available
        trySubmitForm();
    }
    // Handle case where we only have a username/email field (first step of multi-step login)
    else if (usernameField && !passwordField) {
        console.log('Filling username/email field only (multi-step login)');
        
        // Fill the username field
        usernameField.value = password.username;
        usernameField.dispatchEvent(new Event('input', { bubbles: true }));
        usernameField.dispatchEvent(new Event('change', { bubbles: true }));
        
        // For Google specifically, trigger additional events
        if (window.location.hostname.includes('google.com')) {
            usernameField.dispatchEvent(new Event('keyup', { bubbles: true }));
            usernameField.dispatchEvent(new Event('blur', { bubbles: true }));
            
            // For Google, we need to wait a bit for the UI to update before clicking next
            setTimeout(() => {
                trySubmitForm('Filled email/username. Proceeding to password step...');
            }, 1000);
        } else {
            // Try to find and click the next/submit button
            trySubmitForm('Filled email/username. Proceeding to password step...');
        }
    }
    // Handle case where we only have a password field (second step of multi-step login)
    else if (!usernameField && passwordField) {
        console.log('Filling password field only (multi-step login)');
        
        // Fill the password field
        passwordField.value = password.password;
        passwordField.dispatchEvent(new Event('input', { bubbles: true }));
        passwordField.dispatchEvent(new Event('change', { bubbles: true }));
        
        // For Google specifically, trigger additional events
        if (window.location.hostname.includes('google.com')) {
            passwordField.dispatchEvent(new Event('keyup', { bubbles: true }));
            passwordField.dispatchEvent(new Event('blur', { bubbles: true }));
        }
        
        // Try to find and click the submit button
        trySubmitForm();
    }
    else {
        console.error('No fields to fill');
        return; // No fields to fill
    }
    
    // Show a success message
    showSuccessMessage('Credentials autofilled');
}

// Helper function to try submitting the form
function trySubmitForm(customMessage) {
    if (!loginForm) return false;
    
    console.log('Attempting to submit form or click submit button');
    
    // Google-specific selectors
    if (window.location.hostname.includes('google.com')) {
        console.log('Detected Google login form, using Google-specific selectors');
        
        // Google uses these selectors for their login buttons
        const googleSelectors = [
            'button[jsname="LgbsSe"]', // Common Google next/submit button
            'div[jsname="Njthtb"]',   // Another Google button variant
            'div[data-is-touch-wrapper="true"] button', // Touch-enabled button
            'button.VfPpkd-LgbsSe',   // Material design button
            'button.gws-signin-button', // Sign in button
            'button#identifierNext',   // "Next" button on email page
            'button#passwordNext',     // "Next" button on password page
            'input#next',              // Older next button
            'div[role="button"][tabindex="0"]' // Clickable div button
        ];
        
        // Try each Google selector
        for (const selector of googleSelectors) {
            const button = document.querySelector(selector);
            if (button) {
                console.log('Found Google button with selector:', selector);
                
                // Show a message to the user if provided
                if (customMessage) {
                    showSuccessMessage(customMessage);
                }
                
                // Click the button after a short delay
                setTimeout(() => {
                    console.log('Clicking Google button');
                    button.click();
                    button.dispatchEvent(new Event('click', { bubbles: true }));
                }, 500);
                
                return true;
            }
        }
    }
    
    // Try to find a submit button with various selectors
    const submitSelectors = [
        'button[type="submit"]', 
        'input[type="submit"]', 
        'button:not([type])', 
        '[role="button"]', 
        'button[aria-label*="sign in"]', 
        'button[aria-label*="log in"]', 
        'button[aria-label*="login"]', 
        'button[aria-label*="continue"]', 
        'button[aria-label*="next"]', 
        '.login-button', 
        '.signin-button', 
        '.submit-button',
        // Apple-specific selectors
        'button.sign-in-button',
        'button#sign-in',
        // Additional common selectors
        'button.submit',
        'button.login',
        'button.continue',
        'button.next-button',
        'button:contains("Sign In")',
        'button:contains("Log In")',
        'button:contains("Continue")',
        'button:contains("Next")'
    ];
    
    // Try each selector, first within the login form, then in the entire document
    for (const selector of submitSelectors) {
        // First try within the login form
        let submitButton = null;
        try {
            submitButton = loginForm.querySelector(selector);
        } catch (e) {
            // Some selectors might not be valid, ignore errors
        }
        
        // If not found in the form, try the entire document
        if (!submitButton) {
            try {
                submitButton = document.querySelector(selector);
            } catch (e) {
                // Ignore errors for invalid selectors
            }
        }
        
        if (submitButton) {
            console.log('Found submit button with selector:', selector);
            
            // Show a message to the user if provided
            if (customMessage) {
                showSuccessMessage(customMessage);
            }
            
            // Click the button after a short delay
            setTimeout(() => {
                console.log('Clicking submit button');
                submitButton.click();
                submitButton.dispatchEvent(new Event('click', { bubbles: true }));
            }, 500);
            
            return true;
        }
    }
    
    // If no submit button found, try to submit the form directly if it's a form element
    if (loginForm.tagName === 'FORM') {
        console.log('No submit button found, submitting form directly');
        setTimeout(() => {
            loginForm.submit();
        }, 500);
        return true;
    }
    
    console.log('No submit button or form submission method found');
    return false;
}

// Show a success message
function showSuccessMessage(customMessage = 'Credentials autofilled') {
    const messageElement = document.createElement('div');
    messageElement.style.position = 'fixed';
    messageElement.style.bottom = '20px';
    messageElement.style.left = '50%';
    messageElement.style.transform = 'translateX(-50%)';
    messageElement.style.backgroundColor = '#34A853';
    messageElement.style.color = 'white';
    messageElement.style.padding = '10px 20px';
    messageElement.style.borderRadius = '4px';
    messageElement.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.2)';
    messageElement.style.zIndex = '10001';
    messageElement.style.display = 'flex';
    messageElement.style.alignItems = 'center';
    messageElement.style.gap = '8px';
    messageElement.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16">
            <path fill="currentColor" d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
        </svg>
        ${customMessage}
    `;
    
    // Add the message to the document
    document.body.appendChild(messageElement);
    
    // Remove the message after 3 seconds
    setTimeout(() => {
        document.body.removeChild(messageElement);
    }, 3000);
}

// Check if a password is relevant to the current domain
function isRelevantToCurrentDomain(password, currentDomain) {
    if (!currentDomain) return false;
    
    // Check if the password has a URL that matches the current domain
    if (password.url) {
        try {
            const passwordDomain = new URL(password.url).hostname;
            if (passwordDomain === currentDomain) return true;
        } catch (e) {
            // Invalid URL, ignore
        }
    }
    
    // Check if any of the password's websites match the current domain
    if (password.websites && Array.isArray(password.websites)) {
        for (const website of password.websites) {
            try {
                const websiteDomain = new URL(website).hostname;
                if (websiteDomain === currentDomain) return true;
            } catch (e) {
                // Invalid URL, ignore
            }
        }
    }
    
    // Check if the service name matches the current domain
    const domainParts = currentDomain.split('.');
    const mainDomain = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : currentDomain;
    
    return password.service.toLowerCase().includes(mainDomain.toLowerCase());
}

// Helper function to escape HTML
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Listen for messages from the popup script
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Handle autofill action
    if (message.action === "autofill") {
        console.log('Received autofill message with password for:', message.password.service);
        const password = message.password;
        
        // Check if we have detected a login form
        if (!formDetected) {
            console.log('No form detected yet, attempting to detect forms now');
            // Try to detect forms again
            detectForms();
            
            // If still no form detected, return failure
            if (!formDetected) {
                console.error('Form detection failed after retry');
                sendResponse({ 
                    success: false, 
                    message: "No login form detected. Please make sure you're on a login page." 
                });
                return true;
            }
        }
        
        // Log what we found for debugging
        console.log("Form detected:", {
            formDetected,
            hasUsernameField: !!usernameField,
            hasPasswordField: !!passwordField,
            loginFormTag: loginForm ? loginForm.tagName : 'none'
        });
        
        // Autofill the form
        console.log('Attempting to autofill form with credentials');
        autofillForm(password);
        
        // Return success
        sendResponse({ success: true });
        return true;
    }
});