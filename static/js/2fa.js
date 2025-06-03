document.addEventListener('DOMContentLoaded', function() {
    // Elements for 2FA setup
    const setupTotpBtn = document.getElementById('setup-totp-btn');
    const disableTotpBtn = document.getElementById('disable-totp-btn');
    const totpSetupModal = document.getElementById('totp-setup-modal');
    const closeModalBtn = document.querySelector('.close-modal');
    const setupSteps = document.querySelectorAll('.setup-step');
    const nextStepBtn = document.getElementById('next-step-btn');
    const prevStepBtn = document.getElementById('prev-step-btn');
    const verifyCodeInput = document.getElementById('verify-code');
    const verifyCodeBtn = document.getElementById('verify-code-btn');
    const completeSetupBtn = document.getElementById('complete-setup-btn');
    const qrCodeContainer = document.getElementById('qr-code-container');
    const manualCodeContainer = document.getElementById('manual-code');
    const recoveryCodesContainer = document.getElementById('recovery-codes');
    const verifyError = document.getElementById('verify-error');
    
    let currentStep = 0;
    let recoveryCodesData = [];
    
    // Show/hide setup steps
    function showStep(stepIndex) {
        setupSteps.forEach((step, index) => {
            step.style.display = index === stepIndex ? 'block' : 'none';
        });
        
        // Update buttons visibility
        if (stepIndex === 0) {
            prevStepBtn.style.display = 'none';
            nextStepBtn.style.display = 'inline-block';
            verifyCodeBtn.style.display = 'none';
            completeSetupBtn.style.display = 'none';
        } else if (stepIndex === 1) {
            prevStepBtn.style.display = 'inline-block';
            nextStepBtn.style.display = 'none';
            verifyCodeBtn.style.display = 'inline-block';
            completeSetupBtn.style.display = 'none';
        } else if (stepIndex === 2) {
            prevStepBtn.style.display = 'none';
            nextStepBtn.style.display = 'none';
            verifyCodeBtn.style.display = 'none';
            completeSetupBtn.style.display = 'inline-block';
        }
        
        currentStep = stepIndex;
    }
    
    // Initialize TOTP setup
    function initTotpSetup() {
        fetch('/generate-totp-setup')
            .then(response => response.json())
            .then(data => {
                if (data.qr_code && data.secret) {
                    // Display QR code
                    qrCodeContainer.innerHTML = `<img src="${data.qr_code}" alt="QR Code for 2FA Setup">`;
                    
                    // Display manual code
                    manualCodeContainer.textContent = data.secret;
                    
                    // Show the first step
                    showStep(0);
                }
            })
            .catch(error => {
                console.error('Error generating TOTP setup:', error);
                alert('Failed to initialize 2FA setup. Please try again later.');
            });
    }
    
    // Verify TOTP code
    function verifyTotpCode() {
        const code = verifyCodeInput.value.trim();
        if (!code) {
            verifyError.textContent = 'Please enter the verification code';
            return;
        }
        
        const formData = new FormData();
        formData.append('code', code);
        
        fetch('/verify-totp-setup', {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Store recovery codes
                    recoveryCodesData = data.recovery_codes;
                    
                    // Display recovery codes
                    recoveryCodesContainer.innerHTML = '';
                    recoveryCodesData.forEach(code => {
                        const codeElement = document.createElement('div');
                        codeElement.className = 'recovery-code';
                        codeElement.textContent = code;
                        recoveryCodesContainer.appendChild(codeElement);
                    });
                    
                    // Move to recovery codes step
                    showStep(2);
                    verifyError.textContent = '';
                } else {
                    verifyError.textContent = 'Invalid verification code. Please try again.';
                }
            })
            .catch(error => {
                console.error('Error verifying TOTP code:', error);
                verifyError.textContent = 'Failed to verify code. Please try again.';
            });
    }
    
    // Complete TOTP setup
    function completeTotpSetup() {
        fetch('/complete-totp-setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Close modal and refresh page to update UI
                    totpSetupModal.style.display = 'none';
                    window.location.reload();
                } else {
                    alert('Failed to complete 2FA setup: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error completing TOTP setup:', error);
                alert('Failed to complete 2FA setup. Please try again later.');
            });
    }
    
    // Disable TOTP
    function disableTotp() {
        if (!confirm('Are you sure you want to disable two-factor authentication? This will make your account less secure.')) {
            return;
        }
        
        fetch('/disable-totp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.reload();
                } else {
                    alert('Failed to disable 2FA: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error disabling TOTP:', error);
                alert('Failed to disable 2FA. Please try again later.');
            });
    }
    
    // Event listeners
    if (setupTotpBtn) {
        setupTotpBtn.addEventListener('click', function() {
            totpSetupModal.style.display = 'block';
            initTotpSetup();
        });
    }
    
    if (disableTotpBtn) {
        disableTotpBtn.addEventListener('click', disableTotp);
    }
    
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', function() {
            totpSetupModal.style.display = 'none';
        });
    }
    
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === totpSetupModal) {
            totpSetupModal.style.display = 'none';
        }
    });
    
    if (nextStepBtn) {
        nextStepBtn.addEventListener('click', function() {
            showStep(currentStep + 1);
        });
    }
    
    if (prevStepBtn) {
        prevStepBtn.addEventListener('click', function() {
            showStep(currentStep - 1);
        });
    }
    
    if (verifyCodeBtn) {
        verifyCodeBtn.addEventListener('click', verifyTotpCode);
    }
    
    if (verifyCodeInput) {
        verifyCodeInput.addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                verifyTotpCode();
            }
        });
    }
    
    if (completeSetupBtn) {
        completeSetupBtn.addEventListener('click', completeTotpSetup);
    }
    
    // Download recovery codes
    const downloadCodesBtn = document.getElementById('download-codes');
    if (downloadCodesBtn) {
        downloadCodesBtn.addEventListener('click', function() {
            if (recoveryCodesData && recoveryCodesData.length > 0) {
                // Create text content with recovery codes
                const content = 'KASM WORKSPACE 2FA RECOVERY CODES\n\n' + 
                               'Store these codes in a safe place. Each code can only be used once.\n\n' +
                               recoveryCodesData.join('\n');
                
                // Create a blob with the text content
                const blob = new Blob([content], { type: 'text/plain' });
                
                // Create a download link
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'kasm-2fa-recovery-codes.txt';
                
                // Trigger download
                document.body.appendChild(a);
                a.click();
                
                // Clean up
                setTimeout(function() {
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                }, 100);
            } else {
                alert('No recovery codes available to download.');
            }
        });
    }
});