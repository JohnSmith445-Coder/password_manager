// Global variables
let passwordsData = [];
let filteredPasswords = [];
let currentPasswordId = null;
let currentTab = null;

// DOM elements
const passwordListElement = document.getElementById('passwordList');
const passwordDetailsElement = document.getElementById('passwordDetails');
const searchInput = document.getElementById('passwordSearch');
const loadingSpinner = document.getElementById('loadingSpinner');
const detailsTitleElement = document.getElementById('detailsTitle');
const detailsContentElement = document.getElementById('detailsContent');
const closeDetailsButton = document.getElementById('closeDetails');
const autofillButton = document.getElementById('autofill-button');

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  fetchPasswords();
  getCurrentTab();
  
  // Set up event listeners
  searchInput.addEventListener('input', filterPasswords);
  closeDetailsButton.addEventListener('click', hidePasswordDetails);
  if (autofillButton) {
    autofillButton.addEventListener('click', autofillCurrentTab);
  }
});


// Fetch passwords from the server
async function fetchPasswords() {
    try {
        // Show loading spinner
        loadingSpinner.style.display = 'flex';
        
        // Fetch passwords from the server
        const response = await fetch('http://localhost:5000/api/passwords', {
            credentials: 'include' // Include cookies for authentication
        });

        
        if (!response.ok) {
            throw new Error('Failed to fetch passwords');
        }
        
        // Parse the response
        const data = await response.json();
        passwordsData = data;
        
        // Render the password list
        renderPasswordList(passwordsData);
    } catch (error) {
        console.error('Error fetching passwords:', error);
        passwordListElement.innerHTML = `
            <div class="error-message">
                <i class="fas fa-exclamation-circle"></i>
                <p>Failed to load passwords. Please make sure Kasm Workspace is running.</p>
                <button id="retryButton" class="retry-btn">Retry</button>
            </div>
        `;
        
        // Add event listener to retry button
        document.getElementById('retryButton').addEventListener('click', fetchPasswords);
    } finally {
        // Hide loading spinner
        loadingSpinner.style.display = 'none';
    }
}


// Render the password list
function renderPasswordList(passwords) {
    // Clear the password list
    passwordListElement.innerHTML = '';
    
    if (passwords.length === 0) {
        passwordListElement.innerHTML = `
            <div class="empty-message">
                <i class="fas fa-search"></i>
                <p>No passwords found</p>
            </div>
        `;
        return;
    }
    
    // Sort passwords by service name
    passwords.sort((a, b) => a.service.localeCompare(b.service));
    
    // Create a password item for each password
    passwords.forEach(password => {
        const passwordItem = document.createElement('div');
        passwordItem.className = 'password-item';
        passwordItem.dataset.id = password.id;
        
        // Get the first letter of the service name for the icon
        const firstLetter = password.service.charAt(0).toUpperCase();
        
        passwordItem.innerHTML = `
            <div class="password-icon">
                <i class="fas fa-key"></i>
            </div>
            <div class="password-info">
                <div class="service-name">${escapeHtml(password.service)}</div>
                <div class="username">${escapeHtml(password.username)}</div>
            </div>
        `;
        
        // Add event listener to show password details
        passwordItem.addEventListener('click', () => showPasswordDetails(password));
        
        // Add the password item to the list
        passwordListElement.appendChild(passwordItem);
    });
}

// Show password details
function showPasswordDetails(password) {
    // Store the current password ID
    currentPasswordId = password.id;
    
    // Set the details title
    detailsTitleElement.textContent = password.service;
    
    // Create the details content
    let websitesHtml = '';
    if (password.websites && password.websites.length > 0) {
        websitesHtml = `
            <div class="detail-row">
                <div class="detail-label">URLs:</div>
                <div class="detail-value">
                    <div class="url-list">
                        ${password.websites.map(url => `
                            <div class="url-item">
                                <a href="${escapeHtml(url)}" target="_blank" class="url-link">
                                    ${escapeHtml(url)}
                                    <i class="fas fa-external-link-alt"></i>
                                </a>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    } else if (password.url) {
        websitesHtml = `
            <div class="detail-row">
                <div class="detail-label">URL:</div>
                <div class="detail-value">
                    <div class="url-list">
                        <div class="url-item">
                            <a href="${escapeHtml(password.url)}" target="_blank" class="url-link">
                                ${escapeHtml(password.url)}
                                <i class="fas fa-external-link-alt"></i>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
    
    detailsContentElement.innerHTML = `
        <div class="detail-row">
            <div class="detail-label">Username:</div>
            <div class="detail-value">
                ${escapeHtml(password.username)}
                <button class="copy-btn" data-copy="${escapeHtml(password.username)}">
                    <i class="fas fa-copy"></i> Copy
                </button>
            </div>
        </div>
        
        <div class="detail-row">
            <div class="detail-label">Password:</div>
            <div class="detail-value">
                <div class="password-field">
                    <input type="password" value="${escapeHtml(password.password)}" readonly>
                    <button class="toggle-password">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
                <button class="copy-btn" data-copy="${escapeHtml(password.password)}">
                    <i class="fas fa-copy"></i> Copy
                </button>
            </div>
        </div>
        
        ${websitesHtml}
        
        ${password.category ? `
            <div class="detail-row">
                <div class="detail-label">Category:</div>
                <div class="detail-value">
                    ${escapeHtml(password.category)}
                </div>
            </div>
        ` : ''}
        
        ${password.notes ? `
            <div class="detail-row">
                <div class="detail-label">Notes:</div>
                <div class="detail-value notes">
                    ${escapeHtml(password.notes)}
                </div>
            </div>
        ` : ''}
        
        <div class="detail-row">
            <div class="detail-label">Created:</div>
            <div class="detail-value">
                ${password.created_at}
            </div>
        </div>
    `;
    
    // Add event listeners for copy buttons
    detailsContentElement.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', () => {
            const textToCopy = button.dataset.copy;
            copyToClipboard(textToCopy);
            showToast('Copied to clipboard!', 'success');
        });

    });

    // Add event listener for toggle password button
    const togglePasswordButton = detailsContentElement.querySelector('.toggle-password');
    const passwordInput = detailsContentElement.querySelector('input[type="password"]');
    
    togglePasswordButton.addEventListener('click', () => {
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            togglePasswordButton.innerHTML = '<i class="fas fa-eye-slash"></i>';
        } else {
            passwordInput.type = 'password';
            togglePasswordButton.innerHTML = '<i class="fas fa-eye"></i>';
        }
    });

    
    // Show the password details
    passwordDetailsElement.classList.add('active');
}

// Hide password details
function hidePasswordDetails() {
    passwordDetailsElement.classList.remove('active');
}

// Filter passwords based on search input
function filterPasswords() {
    const searchTerm = searchInput.value.toLowerCase();
    
    if (searchTerm === '') {
        renderPasswordList(passwordsData);
        return;
    }
    
    const filteredPasswords = passwordsData.filter(password => {
        return (
            password.service.toLowerCase().includes(searchTerm) ||
            password.username.toLowerCase().includes(searchTerm) ||
            (password.category && password.category.toLowerCase().includes(searchTerm)) ||
            (password.notes && password.notes.toLowerCase().includes(searchTerm))
        );
    });

    renderPasswordList(filteredPasswords);
}

// Copy text to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}

// Show toast notification
function showToast(message, type = 'info') {
    // Remove existing toast
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }
    
    // Create new toast
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let icon = 'info-circle';
    if (type === 'success') icon = 'check-circle';
    if (type === 'error') icon = 'exclamation-circle';
    if (type === 'warning') icon = 'exclamation-triangle';
    
    toast.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <span>${message}</span>
    `;
    
    // Add toast to the document
    document.body.appendChild(toast);
    
    // Show the toast
    setTimeout(() => toast.classList.add('show'), 10);
    
    // Hide the toast after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
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

// Get the current tab
async function getCurrentTab() {
    try {
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        if (tabs.length > 0) {
            currentTab = tabs[0];
            
            // Update the autofill button visibility based on whether we're on a website
            if (autofillButton) {
                if (currentTab.url && (currentTab.url.startsWith('http://') || currentTab.url.startsWith('https://'))) {
                    autofillButton.style.display = 'flex';
                } else {
                    autofillButton.style.display = 'none';
                }
            }
        }
    } catch (error) {
        console.error('Error getting current tab:', error);
    }
}

// Autofill the current tab with the best matching password
async function autofillCurrentTab() {
    if (!currentTab || !passwordsData.length) {
        showToast('No passwords available for autofill', 'warning');
        return;
    }
    
    try {
        // Get the current URL's domain
        const url = new URL(currentTab.url);
        const domain = url.hostname;
        console.log('Current domain:', domain);
        
        // Find the best matching password for this domain
        let bestMatch = null;
        let bestMatchScore = 0;
        
        console.log('Searching for best match among', passwordsData.length, 'passwords');
        
        for (const password of passwordsData) {
            let score = 0;
            let matchReasons = [];
            
            // Check exact URL match
            if (password.url) {
                try {
                    const passwordUrl = new URL(password.url);
                    if (passwordUrl.hostname === domain) {
                        score += 10;
                        matchReasons.push(`URL match: ${passwordUrl.hostname}`);
                    }
                } catch (e) {
                    // Invalid URL, ignore
                }
            }
            
            // Check websites array
            if (password.websites && Array.isArray(password.websites)) {
                for (const website of password.websites) {
                    try {
                        const websiteUrl = new URL(website);
                        if (websiteUrl.hostname === domain) {
                            score += 10;
                            matchReasons.push(`Website match: ${websiteUrl.hostname}`);
                            break;
                        }
                    } catch (e) {
                        // Invalid URL, ignore
                    }
                }
            }
            
            // Check service name match with domain
            const domainParts = domain.split('.');
            const mainDomain = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : domain;
            
            if (password.service.toLowerCase().includes(mainDomain.toLowerCase())) {
                score += 5;
                matchReasons.push(`Service name match: ${password.service} contains ${mainDomain}`);
            }
            
            // For Google specifically, add extra matching logic
            if (domain.includes('google.com') && password.service.toLowerCase().includes('google')) {
                score += 15;
                matchReasons.push('Google-specific match');
            }
            
            console.log(`Password for ${password.service}: score=${score}`, matchReasons.length > 0 ? matchReasons : 'No matches');
            
            // Update best match if this password has a higher score
            if (score > bestMatchScore) {
                bestMatch = password;
                bestMatchScore = score;
            }
        }
        
        // If no match found, show all passwords for manual selection
        if (!bestMatch || bestMatchScore === 0) {
            showToast('No matching password found for this site', 'warning');
            return;
        }
        
        console.log('Best match found:', bestMatch.service, 'with score', bestMatchScore);
        
        // Send message to content script to autofill the form
        console.log('Sending autofill message to tab', currentTab.id);
        const response = await browser.tabs.sendMessage(currentTab.id, {
            action: 'autofill',
            password: bestMatch
        });
        
        console.log('Autofill response:', response);
        
        // Check if autofill was successful
        if (response && response.success) {
            showToast('Credentials autofilled successfully', 'success');
            window.close(); // Close the popup after successful autofill
        } else {
            showToast(response?.message || 'No login form detected on this page', 'warning');
        }
    } catch (error) {
        console.error('Error autofilling form:', error);
        showToast('Failed to autofill form: ' + error.message, 'error');
    }
}